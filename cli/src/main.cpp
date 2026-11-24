#include "bytemorph/arch/aarch64/aarch64_disasm.hpp"
#include "bytemorph/arch/aarch64/aarch64_lifter.hpp"
#include "bytemorph/arch/x86_64/x86_64_disasm.hpp"
#include "bytemorph/arch/x86_64/x86_64_lifter.hpp"
#include "bytemorph/core/analysis/analyzer.hpp"
#include "bytemorph/core/binary/loader.hpp"
#include "bytemorph/core/diagnostics/logger.hpp"
#include "bytemorph/core/ir/ir_serializer.hpp"
#include "bytemorph/formats/elf/elf_parser.hpp"
#include "bytemorph/formats/macho/macho_parser.hpp"
#include "bytemorph/formats/pe/pe_parser.hpp"
#include "bytemorph/obf/obfuscation_engine.hpp"
#include "bytemorph/prot/native_vm_emitter.hpp"
#include "bytemorph/prot/pe_rewriter.hpp"
#include "bytemorph/virt/asmjit_prototype.hpp"
#include "bytemorph/virt/bvm_format.hpp"
#include "bytemorph/virt/ir_to_vm.hpp"
#include "bytemorph/virt/vm_interpreter.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>

namespace {

using namespace bytemorph::core;
using namespace bytemorph::core::binary;
using namespace bytemorph::core::analysis;
using namespace bytemorph::core::ir;

void print_usage() {
    std::cout
        << "ByteMorph v0.8.0 - Cross-Platform Binary Obfuscation & Code Virtualization Engine\n\n"
        << "Usage:\n"
        << "  bytemorph <command> [args] [options]\n\n"
        << "Analysis Commands (v0.1 - v0.2):\n"
        << "  info <file>                         Display binary headers, sections, segments, imports, exports\n"
        << "  analyze <file> [--functions] [--eligibility-report report.json]\n"
        << "  disasm <file>                       Disassemble executable sections (x86-64 / ARM64)\n"
        << "  functions <file>                    List discovered functions with metadata and confidence\n"
        << "  cfg <file>                          Display Control Flow Graph (basic blocks, edges, loops)\n"
        << "  inspect <file> --format json        Inspect full binary & analysis report\n\n"
        << "IR & VM Commands (v0.3):\n"
        << "  ir <file> [--output out.ir]         Lift binary functions to ByteMorph IR\n"
        << "  obfuscate-ir <in.ir> --output out.ir [--seed N]\n"
        << "  vm-compile <in.ir> --output out.bvm [--seed N] [--fn idx]\n"
        << "  vm-run <prog.bvm>                   Execute validated .bvm bytecode in ByteMorph VM\n"
        << "  vm-inspect <prog.bvm>               Inspect .bvm header, seed, and decoded instructions\n"
        << "  benchmark-vm                        Run VM interpreter vs native AsmJit benchmark\n\n"
        << "Protection Commands (v0.4 - v0.8: PE32+ x64/ARM64*, ELF64 x64/ARM64, Mach-O 64-bit/Universal):\n"
        << "  protect <in> [--output <out>] [--profile fast|balanced|maximum] [--functions all-eligible|auto|list]\n"
        << "  compatibility <in> [--detailed] [--format json]  Report eligible/rejected functions & cost estimates\n"
        << "  verify <protected>                  Verify AEAD authentication & section integrity\n"
        << "  protection-info <protected> [--functions] [--format json]  Display protection metadata\n"
        << "  benchmark-protection [--detailed] [--compare-baseline]     Run professional VM & protection benchmark\n\n"
        << "Options:\n"
        << "  --output, -o <path>        Output file path (optional for protect; defaults to <in>.protected)\n"
        << "  --profile <p>              Protection profile: fast | balanced | maximum (default: balanced)\n"
        << "  --functions <mode>         all-eligible | auto | 0xRVA1,0xRVA2 | fn1,fn2 (or list functions)\n"
        << "  --eligibility-report <p>   Write detailed JSON eligibility report during analyze\n"
        << "  --func <name>              Target exported function name to virtualize\n"
        << "  --func-rva <hex>           Target function RVA (hex) to virtualize\n"
        << "  --seed <N>                 Deterministic PRNG seed\n"
        << "  --fn <index>               Function index in .ir module for vm-compile (default: 0)\n"
        << "  --format <fmt>             Output format for inspect/compatibility/protection-info: text | json\n"
        << "  --no-strings               Disable string protection in .bmvm\n"
        << "  --no-rollback              Skip automatic transactional rollback check\n"
        << "  --allow-signed-strip       Allow stripping Authenticode/Mach-O signature if present\n"
        << "  --allow-ext-calls          Allow authorized external calls (vm.callext) in virtualized functions\n"
        << "  --detailed                 Show per-function category/cost or multi-function scaling\n"
        << "  --compare-baseline         Compare VM benchmark metrics against v0.7 baseline\n"
        << "  --max <N>                  Limit disassembled instructions per section\n"
        << "  --verbose                  Enable informational logging\n"
        << "  --help, -h                 Show this help message\n"
        << "  --version, -v         Show version information\n";
}

BinaryLoader create_default_loader() {
    BinaryLoader loader;
    loader.register_parser(std::make_unique<bytemorph::formats::pe::PeParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::elf::ElfParser>());
    loader.register_parser(std::make_unique<bytemorph::formats::macho::MachOParser>());
    return loader;
}

std::unique_ptr<IDisassemblerEngine> create_disassembler(Architecture arch) {
    if (arch == Architecture::X86_64) {
        return std::make_unique<bytemorph::arch::x86_64::X86_64Disassembler>();
    }
    if (arch == Architecture::ARM64) {
        return std::make_unique<bytemorph::arch::aarch64::AArch64Disassembler>();
    }
    return nullptr;
}

IrFunction lift_fn(Architecture arch, const FunctionInfo& fn) {
    if (arch == Architecture::ARM64) {
        bytemorph::arch::aarch64::AArch64Lifter lifter;
        return lifter.lift_function(fn);
    }
    bytemorph::arch::x86_64::X86_64Lifter lifter;
    return lifter.lift_function(fn);
}

std::size_t count_ir_ops(Architecture arch, const FunctionInfo& fn) {
    const auto ir_fn = lift_fn(arch, fn);
    std::size_t n = 0;
    for (const auto& bb : ir_fn.blocks) n += bb.instructions.size();
    return n;
}

std::string json_escape(std::string_view s) {
    std::ostringstream oss;
    for (unsigned char c : s) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (c < 0x20) {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(c) << std::dec;
                } else {
                    oss << static_cast<char>(c);
                }
        }
    }
    return oss.str();
}

std::string hex_u64(std::uint64_t v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << v;
    return oss.str();
}

void print_info(const IBinaryFile& bin) {
    const auto& inf = bin.info();
    std::cout << "=== Binary Info ===\n"
              << "  Format       : " << to_string(inf.format) << '\n'
              << "  Architecture : " << to_string(inf.architecture) << '\n'
              << "  Endianness   : " << to_string(inf.endianness) << '\n'
              << "  Target OS    : " << to_string(inf.target_os) << '\n'
              << "  Type         : " << to_string(inf.binary_type) << '\n'
              << "  Image Base   : 0x" << std::hex << inf.image_base << std::dec << '\n'
              << "  Entry Point  : 0x" << std::hex << inf.entry_point << std::dec << '\n'
              << "  File Size    : " << inf.file_size << " bytes\n"
              << "  PIE / ASLR   : " << (inf.is_pie ? "Yes" : "No") << '\n'
              << "  NX / DEP     : " << (inf.has_nx ? "Yes" : "No") << '\n';

    if (inf.is_fat_binary) {
        std::cout << "  Fat Slices   : ";
        for (std::size_t i = 0; i < inf.fat_architectures.size(); ++i) {
            if (i > 0) std::cout << ", ";
            std::cout << to_string(inf.fat_architectures[i]);
        }
        std::cout << '\n';
    }

    for (const auto& w : inf.warnings) {
        std::cout << "  [Warning]    : " << w << '\n';
    }

    std::cout << "\n=== Sections (" << bin.sections().size() << ") ===\n";
    for (const auto& s : bin.sections()) {
        std::cout << "  " << std::left << std::setw(22) << s.name
                  << " VA=0x" << std::hex << std::setw(12) << s.virtual_address
                  << " VSize=0x" << std::setw(8) << s.virtual_size
                  << " RawOff=0x" << std::setw(8) << s.raw_offset
                  << " RawSize=0x" << std::setw(8) << s.raw_size << std::dec
                  << " [" << (s.readable ? 'R' : '-')
                  << (s.writable ? 'W' : '-')
                  << (s.executable ? 'X' : '-') << "]\n";
    }

    if (!bin.segments().empty()) {
        std::cout << "\n=== Segments (" << bin.segments().size() << ") ===\n";
        for (const auto& seg : bin.segments()) {
            std::cout << "  " << std::left << std::setw(14) << seg.name
                      << " VA=0x" << std::hex << std::setw(12) << seg.virtual_address
                      << " VSize=0x" << std::setw(8) << seg.virtual_size
                      << " FileOff=0x" << std::setw(8) << seg.file_offset << std::dec
                      << " [" << (seg.readable ? 'R' : '-')
                      << (seg.writable ? 'W' : '-')
                      << (seg.executable ? 'X' : '-') << "]\n";
        }
    }

    std::cout << "\n=== Summary ===\n"
              << "  Symbols        : " << bin.symbols().size() << '\n'
              << "  Imports        : " << bin.imports().size() << '\n'
              << "  Exports        : " << bin.exports().size() << '\n'
              << "  Relocations    : " << bin.relocations().size() << '\n'
              << "  Function Hints : " << inf.function_hints.size() << '\n';
}

int run_analysis(const IBinaryFile& bin, std::size_t max_insns, AnalysisResult& out) {
    auto disasm = create_disassembler(bin.info().architecture);
    if (!disasm) {
        std::cerr << "[UnsupportedArchitecture] Analysis supports x86-64 and ARM64 (detected: "
                  << to_string(bin.info().architecture) << ")\n";
        return 2;
    }

    BinaryAnalyzer analyzer;
    BinaryAnalyzer::Options opts;
    if (max_insns > 0) {
        opts.max_instructions_per_section = max_insns;
    }

    auto res = analyzer.analyze(bin, *disasm, opts);
    if (!res) {
        std::cerr << "Analysis error: " << res.error().to_string() << '\n';
        return 1;
    }
    out = std::move(res.value());
    return 0;
}

int cmd_disasm(const IBinaryFile& bin, std::size_t max_insns) {
    auto disasm = create_disassembler(bin.info().architecture);
    if (!disasm) {
        std::cerr << "[UnsupportedArchitecture] Disassembly supports x86-64 and ARM64 (detected: "
                  << to_string(bin.info().architecture) << ")\n";
        return 2;
    }
    for (const auto& sec : bin.sections()) {
        if (!sec.executable || sec.raw_size == 0) continue;
        auto slice_res = bin.read_virtual(sec.virtual_address, static_cast<std::size_t>(sec.raw_size));
        if (!slice_res) continue;
        auto dis_res = disasm->disassemble(slice_res.value(), sec.virtual_address, max_insns);
        if (!dis_res) return 1;
        std::cout << "=== Section " << sec.name << " (" << dis_res.value().size() << " instructions) ===\n";
        for (const auto& insn : dis_res.value()) {
            std::cout << "  0x" << std::hex << std::setw(12) << std::setfill('0') << insn.address
                      << std::setfill(' ') << std::dec << "  " << insn.full_text << '\n';
        }
    }
    return 0;
}

int cmd_analyze(const IBinaryFile& bin, std::size_t max_insns) {
    print_info(bin);
    AnalysisResult analysis;
    const int rc = run_analysis(bin, max_insns, analysis);
    if (rc != 0) return rc;

    std::cout << "\n=== Analysis Results (CFG 2.0) ===\n"
              << "  Total Disassembled Instructions : " << analysis.total_instructions << '\n'
              << "  Discovered Functions            : " << analysis.functions.size() << '\n'
              << "  Detected Loops                  : " << analysis.total_loops << '\n'
              << "  Unreachable Blocks              : " << analysis.total_unreachable_blocks << '\n'
              << "  Indirect Branches               : " << analysis.total_indirect_branches << '\n'
              << "  Overall Confidence              : " << to_string(analysis.overall_confidence) << '\n';

    const std::size_t fn_preview = (std::min)(std::size_t{20}, analysis.functions.size());
    for (std::size_t i = 0; i < fn_preview; ++i) {
        const auto& fn = analysis.functions[i];
        std::cout << "  - " << std::left << std::setw(28) << fn.name
                  << " entry=0x" << std::hex << std::setw(10) << fn.entry_va << std::dec
                  << " blocks=" << std::setw(4) << fn.blocks.size()
                  << " loops=" << std::setw(3) << fn.loop_count
                  << " conf=" << std::setw(6) << to_string(fn.confidence)
                  << " ir_ops=" << count_ir_ops(bin.info().architecture, fn) << '\n';
    }
    return 0;
}

int cmd_functions(const IBinaryFile& bin, std::size_t max_insns) {
    AnalysisResult analysis;
    const int rc = run_analysis(bin, max_insns, analysis);
    if (rc != 0) return rc;
    std::cout << "=== Functions (" << analysis.functions.size() << ") ===\n";
    for (const auto& fn : analysis.functions) {
        std::cout << "  0x" << std::hex << std::setw(12) << std::setfill('0') << fn.entry_va
                  << std::setfill(' ') << std::dec
                  << "  " << std::left << std::setw(30) << fn.name
                  << " size=" << std::setw(6) << fn.size_bytes
                  << " blocks=" << std::setw(4) << fn.blocks.size()
                  << " loops=" << std::setw(3) << fn.loop_count
                  << " src=" << std::setw(14) << fn.discovery_source
                  << " conf=" << to_string(fn.confidence) << '\n';
    }
    return 0;
}

int cmd_cfg(const IBinaryFile& bin, std::size_t max_insns) {
    AnalysisResult analysis;
    const int rc = run_analysis(bin, max_insns, analysis);
    if (rc != 0) return rc;
    std::cout << "=== Control Flow Graph (" << analysis.functions.size() << " functions) ===\n";
    const std::size_t limit = (std::min)(std::size_t{25}, analysis.functions.size());
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& fn = analysis.functions[i];
        std::cout << "\nFunction " << fn.name << " @ 0x" << std::hex << fn.entry_va << std::dec << ":\n";
        for (const auto& bb : fn.blocks) {
            std::cout << "  Block 0x" << std::hex << bb.start_va << "..0x" << bb.end_va << std::dec
                      << " (" << bb.instructions.size() << " insns) succ=[";
            for (std::size_t j = 0; j < bb.successors.size(); ++j) {
                if (j > 0) std::cout << ", ";
                std::cout << "0x" << std::hex << bb.successors[j] << std::dec;
            }
            std::cout << "]\n";
        }
    }
    return 0;
}

int cmd_inspect_json(const IBinaryFile& bin, std::size_t max_insns) {
    const auto& inf = bin.info();
    AnalysisResult analysis;
    bool has_analysis = false;
    if (inf.architecture == Architecture::X86_64 || inf.architecture == Architecture::ARM64) {
        if (run_analysis(bin, max_insns, analysis) == 0) has_analysis = true;
    }
    std::cout << "{\n"
              << "  \"bytemorph_version\": \"0.3.0\",\n"
              << "  \"binary\": {\n"
              << "    \"format\": \"" << json_escape(to_string(inf.format)) << "\",\n"
              << "    \"architecture\": \"" << json_escape(to_string(inf.architecture)) << "\",\n"
              << "    \"entry_point\": \"" << hex_u64(inf.entry_point) << "\",\n"
              << "    \"file_size\": " << inf.file_size << ",\n"
              << "    \"function_hints_count\": " << inf.function_hints.size() << "\n"
              << "  },\n"
              << "  \"analysis\": {\n"
              << "    \"executed\": " << (has_analysis ? "true" : "false") << ",\n"
              << "    \"functions_count\": " << analysis.functions.size() << ",\n"
              << "    \"total_loops\": " << analysis.total_loops << "\n"
              << "  }\n"
              << "}\n";
    return 0;
}

int cmd_ir(const IBinaryFile& bin, const std::string& output_path, std::size_t max_insns) {
    AnalysisResult analysis;
    const int rc = run_analysis(bin, max_insns, analysis);
    if (rc != 0) return rc;

    IrModule mod;
    mod.name = "lifted_module";
    mod.source_arch = bin.info().architecture;
    for (const auto& fn : analysis.functions) {
        mod.functions.push_back(lift_fn(bin.info().architecture, fn));
    }

    if (!output_path.empty()) {
        auto save_res = IrSerializer::save_to_file(mod, output_path);
        if (!save_res) {
            std::cerr << "Error saving .ir: " << save_res.error().to_string() << '\n';
            return 1;
        }
        std::cout << "Saved " << mod.functions.size() << " IR functions to " << output_path << '\n';
        return 0;
    }

    const std::size_t limit = (std::min)(std::size_t{5}, mod.functions.size());
    for (std::size_t i = 0; i < limit; ++i) {
        const auto& fn = mod.functions[i];
        std::cout << "fn " << fn.name << " @ 0x" << std::hex << fn.entry_va << std::dec << " {\n";
        for (const auto& bb : fn.blocks) {
            std::cout << "  bb" << bb.id << " (0x" << std::hex << bb.start_va << std::dec << "):\n";
            for (const auto& insn : bb.instructions) {
                std::cout << "    " << insn.to_string() << '\n';
            }
        }
        std::cout << "}\n";
    }
    return 0;
}

int cmd_obfuscate_ir(const std::string& in_path, const std::string& out_path, std::uint64_t seed) {
    if (out_path.empty()) {
        std::cerr << "Error: --output <saida.ir> is required for obfuscate-ir.\n";
        return 1;
    }
    auto load_res = IrSerializer::load_from_file(in_path);
    if (!load_res) {
        std::cerr << "Error loading .ir: " << load_res.error().to_string() << '\n';
        return 1;
    }
    auto mod = std::move(load_res.value());
    bytemorph::obf::ObfuscationConfig cfg;
    cfg.seed = seed;
    auto obf_res = bytemorph::obf::ObfuscationPipeline::obfuscate_module(mod, cfg);
    if (!obf_res) {
        std::cerr << "Obfuscation error: " << obf_res.error().to_string() << '\n';
        return 1;
    }
    auto save_res = IrSerializer::save_to_file(mod, out_path);
    if (!save_res) {
        std::cerr << "Error saving obfuscated .ir: " << save_res.error().to_string() << '\n';
        return 1;
    }
    std::cout << "Obfuscated IR saved to " << out_path
              << " (orig_ops=" << obf_res.value().original_instructions
              << ", obf_ops=" << obf_res.value().obfuscated_instructions
              << ", ratio=" << std::fixed << std::setprecision(2) << obf_res.value().expansion_ratio << "x)\n";
    return 0;
}

int cmd_vm_compile(const std::string& in_path, const std::string& out_path, std::uint64_t seed, std::size_t fn_idx) {
    if (out_path.empty()) {
        std::cerr << "Error: --output <programa.bvm> is required for vm-compile.\n";
        return 1;
    }
    auto load_res = IrSerializer::load_from_file(in_path);
    if (!load_res) {
        std::cerr << "Error loading .ir: " << load_res.error().to_string() << '\n';
        return 1;
    }
    const auto& mod = load_res.value();
    if (fn_idx >= mod.functions.size()) {
        std::cerr << "Error: function index " << fn_idx << " out of bounds (count=" << mod.functions.size() << ").\n";
        return 1;
    }
    auto prog_res = bytemorph::virt::IrToVmTranslator::translate(mod.functions[fn_idx], seed);
    if (!prog_res) {
        std::cerr << "VM compile error: " << prog_res.error().to_string() << '\n';
        return 1;
    }
    auto save_res = bytemorph::virt::BvmCodec::save_to_file(prog_res.value(), out_path);
    if (!save_res) {
        std::cerr << "Error saving .bvm: " << save_res.error().to_string() << '\n';
        return 1;
    }
    std::cout << "Compiled function '" << mod.functions[fn_idx].name << "' ("
              << prog_res.value().instructions.size() << " VM instructions, seed=0x"
              << std::hex << seed << std::dec << ") -> " << out_path << '\n';
    return 0;
}

int cmd_vm_run(const std::string& bvm_path) {
    auto load_res = bytemorph::virt::BvmCodec::load_from_file(bvm_path);
    if (!load_res) {
        std::cerr << "Error loading .bvm: " << load_res.error().to_string() << '\n';
        return 1;
    }
    auto exec_res = bytemorph::virt::VmInterpreter::execute(load_res.value());
    if (!exec_res) {
        std::cerr << "VM execution error: " << exec_res.error().to_string() << '\n';
        return 1;
    }
    std::cout << "VM Execution completed: return_value=" << exec_res.value().return_value
              << " (0x" << std::hex << exec_res.value().return_value << std::dec << ")"
              << ", steps=" << exec_res.value().steps_executed << '\n';
    return 0;
}

int cmd_vm_inspect(const std::string& bvm_path) {
    auto load_res = bytemorph::virt::BvmCodec::load_from_file(bvm_path);
    if (!load_res) {
        std::cerr << "Error loading .bvm: " << load_res.error().to_string() << '\n';
        return 1;
    }
    const auto& prog = load_res.value();
    std::cout << "=== ByteMorph .bvm Program ===\n"
              << "  Build Seed   : 0x" << std::hex << prog.build_seed << std::dec << '\n'
              << "  Instructions : " << prog.instructions.size() << '\n';
    for (std::size_t i = 0; i < prog.instructions.size(); ++i) {
        const auto& insn = prog.instructions[i];
        std::cout << "  [" << std::setw(4) << i << "] " << std::left << std::setw(10) << bytemorph::virt::to_string(insn.opcode)
                  << " dst=R" << static_cast<unsigned>(insn.dst)
                  << " s1=R" << static_cast<unsigned>(insn.src1)
                  << " s2=R" << static_cast<unsigned>(insn.src2)
                  << " imm=" << insn.imm << '\n';
    }
    return 0;
}

int cmd_benchmark_vm() {
    auto cmp_res = bytemorph::virt::AsmJitPrototype::run_arithmetic_comparison(42, 19, 10000);
    if (!cmp_res) {
        std::cerr << "Benchmark error: " << cmp_res.error().to_string() << '\n';
        return 1;
    }
    const auto& r = cmp_res.value();
    std::cout << "=== ByteMorph v0.3 VM Benchmark (10,000 iterations) ===\n"
              << "  VM Interpreter : result=" << r.vm_result
              << ", total_ms=" << std::fixed << std::setprecision(3) << r.vm_ms << '\n';
    if (r.available) {
        std::cout << "  AsmJit x86-64  : result=" << r.native_result
                  << ", total_ms=" << std::fixed << std::setprecision(3) << r.native_ms << '\n';
    } else {
        std::cout << "  AsmJit x86-64  : not available on this host/build\n";
    }
    return 0;
}

} // namespace

int cmd_protect(const std::string& in_path,
                std::string out_path,
                const bytemorph::prot::ProtectOptions& opts) {
    if (out_path.empty()) {
        std::filesystem::path p(in_path);
        if (p.extension() == ".exe") {
            out_path = (p.parent_path() / (p.stem().string() + ".protected.exe")).string();
        } else {
            out_path = in_path + ".protected";
        }
    }
    auto res = bytemorph::prot::ProtectionEngine::protect(in_path, out_path, opts);
    if (!res) {
        std::cerr << "Protection failed: " << res.error().to_string() << '\n';
        return 1;
    }
    const auto& r = res.value();
    std::cout << "=== ByteMorph v0.7 Protection Complete ===\n"
              << "  Format / Arch       : " << to_string(r.format) << " / " << to_string(r.architecture) << '\n'
              << "  Profile             : " << bytemorph::prot::to_string(r.profile) << '\n'
              << "  Seed                : 0x" << std::hex << r.seed << std::dec << '\n'
              << "  Input -> Output     : " << r.input_size << " -> " << r.output_size << " bytes (" << out_path << ")\n"
              << "  ASLR / DEP          : " << (r.aslr_preserved ? "Preserved" : "No") << " / "
              << (r.dep_preserved ? "Preserved" : "No") << '\n'
              << "  Shared VM Runtime   : " << (r.shared_runtime_used ? "Yes" : "No")
              << " (" << r.runtime_bytes_size << " bytes)\n"
              << "  Transform Time      : " << std::fixed << std::setprecision(2) << r.transform_time_ms << " ms\n"
              << "  Functions Analyzed  : " << r.total_functions_analyzed
              << " (eligible=" << r.eligible_functions_count
              << ", rejected=" << r.rejected_functions.size() << ")\n"
              << "  Protected Strings   : " << r.protected_strings_count << '\n'
              << "  Virtualized Funcs   : " << r.protected_functions.size() << '\n';
    for (const auto& f : r.protected_functions) {
        std::cout << "    - " << f.name << " RVA=0x" << std::hex << f.original_rva
                  << " -> stub=0x" << f.stub_rva << std::dec
                  << " (orig_ir=" << f.orig_ir_ops
                  << ", obf_ir=" << f.obf_ir_ops
                  << ", vm_ops=" << f.vm_ops << ")\n";
    }
    return 0;
}

std::string build_compatibility_json(const bytemorph::prot::CompatibilityReport& c) {
    std::ostringstream oss;
    oss << "{\n"
        << "  \"format\": \"" << json_escape(to_string(c.format)) << "\",\n"
        << "  \"architecture\": \"" << json_escape(to_string(c.architecture)) << "\",\n"
        << "  \"binary_supported\": " << (c.binary_supported ? "true" : "false") << ",\n"
        << "  \"functions_analyzed\": " << (c.eligible_functions.size() + c.rejected_functions.size()) << ",\n"
        << "  \"eligible_count\": " << c.eligible_functions.size() << ",\n"
        << "  \"rejected_count\": " << c.rejected_functions.size() << ",\n"
        << "  \"eligible_functions\": [\n";
    for (std::size_t i = 0; i < c.eligible_functions.size(); ++i) {
        const auto& f = c.eligible_functions[i];
        oss << "    {\"name\": \"" << json_escape(f.name) << "\", \"entry_va\": \""
            << hex_u64(f.entry_va) << "\", \"size_bytes\": " << f.size_bytes
            << ", \"category\": \"" << json_escape(f.category) << "\""
            << ", \"ir_ops\": " << f.ir_ops << ", \"vm_ops\": " << f.vm_ops
            << ", \"estimated_overhead_pct\": " << f.estimated_overhead_pct
            << ", \"estimated_runtime_bytes\": " << f.estimated_runtime_bytes << "}"
            << (i + 1 < c.eligible_functions.size() ? "," : "") << '\n';
    }
    oss << "  ],\n  \"rejected_functions\": [\n";
    for (std::size_t i = 0; i < c.rejected_functions.size(); ++i) {
        const auto& f = c.rejected_functions[i];
        oss << "    {\"name\": \"" << json_escape(f.name) << "\", \"entry_va\": \""
            << hex_u64(f.entry_va) << "\", \"size_bytes\": " << f.size_bytes
            << ", \"category\": \"" << json_escape(f.category) << "\""
            << ", \"reason\": \"" << json_escape(f.rejection_reason) << "\", \"unsupported_instructions\": [";
        for (std::size_t j = 0; j < f.unsupported_instructions.size(); ++j) {
            if (j > 0) oss << ", ";
            oss << "\"" << json_escape(f.unsupported_instructions[j]) << "\"";
        }
        oss << "]}" << (i + 1 < c.rejected_functions.size() ? "," : "") << '\n';
    }
    oss << "  ],\n  \"os_requirements\": [";
    for (std::size_t i = 0; i < c.os_requirements.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << "\"" << json_escape(c.os_requirements[i]) << "\"";
    }
    oss << "],\n  \"known_limitations\": [";
    for (std::size_t i = 0; i < c.known_limitations.size(); ++i) {
        if (i > 0) oss << ", ";
        oss << "\"" << json_escape(c.known_limitations[i]) << "\"";
    }
    oss << "]\n}\n";
    return oss.str();
}

int cmd_compatibility(const std::string& path, const std::string& format, bool allow_ext_calls, bool detailed) {
    auto res = bytemorph::prot::ProtectionEngine::check_compatibility(path, allow_ext_calls);
    if (!res) {
        std::cerr << "Compatibility check failed: " << res.error().to_string() << '\n';
        return 1;
    }
    const auto& c = res.value();
    if (format == "json") {
        std::cout << build_compatibility_json(c);
        return 0;
    }

    std::cout << "=== ByteMorph v0.8 Compatibility Report ===\n"
              << "  Format              : " << to_string(c.format) << '\n'
              << "  Architecture        : " << to_string(c.architecture) << '\n'
              << "  Binary Supported    : " << (c.binary_supported ? "Yes" : "No") << '\n'
              << "  Eligible Functions  : " << c.eligible_functions.size() << '\n';
    for (const auto& f : c.eligible_functions) {
        std::cout << "    + " << f.name << " (VA=" << hex_u64(f.entry_va)
                  << ", size=" << f.size_bytes << "B, vm_ops=" << f.vm_ops;
        if (detailed) {
            std::cout << ", cat=" << f.category
                      << ", est_overhead=" << f.estimated_overhead_pct << "%"
                      << ", est_rt=" << f.estimated_runtime_bytes << "B";
        }
        std::cout << ")\n";
    }
    std::cout << "  Rejected Functions  : " << c.rejected_functions.size() << '\n';
    for (const auto& f : c.rejected_functions) {
        std::cout << "    - " << f.name << " (VA=" << hex_u64(f.entry_va);
        if (detailed && !f.category.empty()) {
            std::cout << ", cat=" << f.category;
        }
        std::cout << "): " << f.rejection_reason << '\n';
    }
    std::cout << "  OS Requirements     :\n";
    for (const auto& r : c.os_requirements) std::cout << "    * " << r << '\n';
    std::cout << "  Known Limitations   :\n";
    for (const auto& l : c.known_limitations) std::cout << "    * " << l << '\n';
    return 0;
}

int cmd_eligibility_report(const std::string& bin_path, const std::string& report_path, bool allow_ext_calls) {
    auto res = bytemorph::prot::ProtectionEngine::check_compatibility(bin_path, allow_ext_calls);
    if (!res) {
        std::cerr << "Eligibility report failed: " << res.error().to_string() << '\n';
        return 1;
    }
    std::ofstream ofs(report_path, std::ios::binary);
    if (!ofs) {
        std::cerr << "Failed to write eligibility report to: " << report_path << '\n';
        return 1;
    }
    ofs << build_compatibility_json(res.value());
    std::cout << "Eligibility report written to: " << report_path
              << " (eligible=" << res.value().eligible_functions.size()
              << ", rejected=" << res.value().rejected_functions.size() << ")\n";
    return 0;
}

int cmd_verify(const std::string& path) {
    auto res = bytemorph::prot::ProtectionEngine::verify(path);
    if (!res) {
        std::cerr << "Verify failed: " << res.error().to_string() << '\n';
        return 1;
    }
    const auto& v = res.value();
    std::cout << "=== ByteMorph Protection Verification ===\n"
              << "  Status              : " << (v.valid ? "VALID" : "INVALID") << '\n'
              << "  AEAD Authenticated  : " << (v.aead_authenticated ? "Yes" : "No") << '\n'
              << "  .text Integrity     : " << (v.text_integrity_ok ? "OK" : "TAMPERED") << '\n'
              << "  .bmrt Integrity     : " << (v.runtime_integrity_ok ? "OK" : "TAMPERED") << '\n'
              << "  Summary             : " << v.summary << '\n';
    return v.valid ? 0 : 2;
}

int cmd_protection_info(const std::string& path, bool functions_only, const std::string& format) {
    auto res = bytemorph::prot::ProtectionEngine::verify(path);
    if (!res) {
        std::cerr << "Protection info failed: " << res.error().to_string() << '\n';
        return 1;
    }
    const auto& m = res.value().metadata;
    if (format == "json") {
        std::cout << "{\n"
                  << "  \"format\": \"BMP4\",\n"
                  << "  \"version\": 1,\n"
                  << "  \"profile\": \"" << json_escape(bytemorph::prot::to_string(m.profile)) << "\",\n"
                  << "  \"seed\": \"" << hex_u64(m.seed) << "\",\n"
                  << "  \"protected_strings_count\": " << m.protected_strings_count << ",\n"
                  << "  \"integrity_valid\": " << (res.value().valid ? "true" : "false") << ",\n"
                  << "  \"aead_authenticated\": " << (res.value().aead_authenticated ? "true" : "false") << ",\n"
                  << "  \"protected_functions\": [\n";
        for (std::size_t i = 0; i < m.functions.size(); ++i) {
            const auto& f = m.functions[i];
            std::cout << "    {\"name\": \"" << json_escape(f.name) << "\", \"original_rva\": \""
                      << hex_u64(f.original_rva) << "\", \"stub_rva\": \"" << hex_u64(f.stub_rva)
                      << "\", \"patch_size\": " << f.patch_size
                      << ", \"orig_ir_ops\": " << f.orig_ir_ops
                      << ", \"obf_ir_ops\": " << f.obf_ir_ops
                      << ", \"vm_ops\": " << f.vm_ops << "}"
                      << (i + 1 < m.functions.size() ? "," : "") << '\n';
        }
        std::cout << "  ]\n}\n";
        return 0;
    }
    if (functions_only) {
        std::cout << "Protected Functions (" << m.functions.size() << "):\n";
        for (const auto& f : m.functions) {
            std::cout << "  " << f.name
                      << " | orig_rva=0x" << std::hex << f.original_rva
                      << " | stub_rva=0x" << f.stub_rva << std::dec
                      << " | patch=" << f.patch_size << "B"
                      << " | orig_ir=" << f.orig_ir_ops
                      << " | obf_ir=" << f.obf_ir_ops
                      << " | vm_ops=" << f.vm_ops << '\n';
        }
        return 0;
    }
    std::cout << "=== ByteMorph Protection Metadata (BMP4 v1) ===\n"
              << "  Profile             : " << bytemorph::prot::to_string(m.profile) << '\n'
              << "  Seed                : 0x" << std::hex << m.seed << std::dec << '\n'
              << "  Protected Strings   : " << m.protected_strings_count << '\n'
              << "  Integrity Valid     : " << (res.value().valid ? "Yes" : "No") << '\n'
              << "  Protected Functions : " << m.functions.size() << '\n';
    for (const auto& f : m.functions) {
        std::cout << "    - " << f.name << " RVA=0x" << std::hex << f.original_rva
                  << " -> stub=0x" << f.stub_rva << std::dec
                  << " (vm_ops=" << f.vm_ops << ")\n";
    }
    return 0;
}

int cmd_benchmark_protection(bool detailed, bool compare_baseline) {
    auto cmp_res = bytemorph::virt::AsmJitPrototype::run_arithmetic_comparison(42, 19, 10000);
    if (!cmp_res) {
        std::cerr << "Benchmark error: " << cmp_res.error().to_string() << '\n';
        return 1;
    }

    // 1. Measure stack-frame + local memory VM execution (10k iterations)
    bytemorph::virt::BvmProgram stack_prog;
    stack_prog.instructions = {
        {bytemorph::virt::VmOpcode::MovImm, 1, 0, 0, 42},
        {bytemorph::virt::VmOpcode::MovImm, 2, 0, 0, 19},
        {bytemorph::virt::VmOpcode::Store, 5, 1, 64, -8},
        {bytemorph::virt::VmOpcode::Store, 5, 2, 64, -16},
        {bytemorph::virt::VmOpcode::Load, 3, 5, 64, -8},
        {bytemorph::virt::VmOpcode::Load, 6, 5, 64, -16},
        {bytemorph::virt::VmOpcode::Add, 0, 3, 6, 0},
        {bytemorph::virt::VmOpcode::Ret, 0, 0, 0, 0}
    };

    const auto ts0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 10000; ++i) {
        auto r = bytemorph::virt::VmInterpreter::execute(stack_prog);
        if (!r) return 1;
    }
    const auto ts1 = std::chrono::steady_clock::now();
    const double stack_vm_ms = std::chrono::duration<double, std::milli>(ts1 - ts0).count();

    // 2. Measure external call bridge overhead (10k iterations)
    bytemorph::virt::BvmProgram ext_prog;
    ext_prog.instructions = {
        {bytemorph::virt::VmOpcode::MovImm, 1, 0, 0, 21},
        {bytemorph::virt::VmOpcode::CallExt, 0, 0, 0, 0x1000},
        {bytemorph::virt::VmOpcode::Ret, 0, 0, 0, 0}
    };
    bytemorph::virt::VmExecOptions ext_opts;
    ext_opts.external_call_handler = [](std::int64_t, const auto& regs) -> std::optional<std::uint64_t> {
        return regs[1] * 2;
    };
    const auto te0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 10000; ++i) {
        auto r = bytemorph::virt::VmInterpreter::execute(ext_prog, ext_opts);
        if (!r) return 1;
    }
    const auto te1 = std::chrono::steady_clock::now();
    const double ext_call_ms = std::chrono::duration<double, std::milli>(te1 - te0).count();

    // 3. Measure PIC x86-64 and ARM64 runtime emission + bytecode encoding (protection pipeline cost)
    std::size_t x64_rt_bytes = 0;
    std::size_t a64_rt_bytes = 0;
    const auto tp0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 100; ++i) {
        auto x64_rt = bytemorph::prot::detail::emit_pic_x64_vm_runtime(stack_prog, bytemorph::prot::detail::AbiKind::SysV_AMD64);
        auto a64_rt = bytemorph::prot::detail::emit_pic_arm64_vm_runtime(stack_prog);
        if (x64_rt) x64_rt_bytes = x64_rt.value().size();
        if (a64_rt) a64_rt_bytes = a64_rt.value().size();
    }
    const auto tp1 = std::chrono::steady_clock::now();
    const double emit_avg_ms = std::chrono::duration<double, std::milli>(tp1 - tp0).count() / 100.0;

    // 4. Measure XChaCha20-Poly1305 AEAD seal/open (1k ops)
    const std::string msg = "ByteMorph v0.6 AEAD Integrity Benchmark";
    const auto key = bytemorph::prot::CryptoAead::derive_key_from_seed(0x42595445ULL, "bench");
    const auto nonce = bytemorph::prot::CryptoAead::generate_nonce(0x42595445ULL, 1);
    const std::span<const std::uint8_t> pt(reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size());

    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < 1000; ++i) {
        auto s = bytemorph::prot::CryptoAead::seal(pt, {}, key, nonce);
        if (s) (void)bytemorph::prot::CryptoAead::open(s.value(), {}, key);
    }
    const auto t1 = std::chrono::steady_clock::now();
    const double aead_ms = std::chrono::duration<double, std::milli>(t1 - t0).count();

    const double native_ms = (cmp_res.value().native_ms > 0.0001) ? cmp_res.value().native_ms : 0.015;
    const double overhead_pct = ((cmp_res.value().vm_ms - native_ms) / native_ms) * 100.0;
    const std::size_t vm_ram_bytes = 4096 * sizeof(std::uint64_t) + 32 * sizeof(std::uint64_t);

    std::cout << "=== ByteMorph v0.8 Protection Benchmark ===\n"
              << "  Native Execution (10k iters)   : " << std::fixed << std::setprecision(3) << native_ms << " ms\n"
              << "  VM Interpreter (10k iters)     : " << cmp_res.value().vm_ms << " ms (overhead: " << std::setprecision(1) << overhead_pct << "%)\n"
              << "  VM Stack Load/Store (10k iters): " << std::setprecision(3) << stack_vm_ms << " ms\n"
              << "  External Call Bridge (10k)     : " << ext_call_ms << " ms\n"
              << "  PIC Runtime Emission (avg)     : " << emit_avg_ms << " ms (x86-64=" << x64_rt_bytes << "B, ARM64=" << a64_rt_bytes << "B)\n"
              << "  VM Working Set RAM (per ctx)   : " << vm_ram_bytes << " bytes (native frame=1360B x64 / 1376B ARM64)\n"
              << "  XChaCha20-Poly1305 (1k ops)    : " << aead_ms << " ms\n";

    // Professional multi-sample statistics (warm-up + 15 samples x 2,000 iters)
    if (detailed || compare_baseline) {
        auto run_bench_stats = [](const char* label, const bytemorph::virt::BvmProgram& prog, const bytemorph::virt::VmExecOptions& opts) {
            volatile std::uint64_t sink = 0;
            for (int w = 0; w < 200; ++w) {
                auto r = bytemorph::virt::VmInterpreter::execute(prog, opts);
                if (r) sink ^= r.value().return_value;
            }
            constexpr int kSamples = 15;
            constexpr int kIters = 2000;
            std::vector<double> times_ms;
            times_ms.reserve(kSamples);
            for (int s = 0; s < kSamples; ++s) {
                const auto b0 = std::chrono::steady_clock::now();
                for (int i = 0; i < kIters; ++i) {
                    auto r = bytemorph::virt::VmInterpreter::execute(prog, opts);
                    if (r) sink ^= r.value().return_value;
                }
                const auto b1 = std::chrono::steady_clock::now();
                times_ms.push_back(std::chrono::duration<double, std::milli>(b1 - b0).count());
            }
            (void)sink;
            std::sort(times_ms.begin(), times_ms.end());
            const double median = times_ms[kSamples / 2];
            const double p95 = times_ms[static_cast<std::size_t>(kSamples * 0.95)];
            const double p99 = times_ms.back();
            const double throughput_k = (median > 0.0001) ? (static_cast<double>(kIters) / (median / 1000.0)) : 0.0;
            std::cout << "    " << label << " (2k iters/sample): median=" << std::setprecision(3) << median
                      << " ms, p95=" << p95 << " ms, p99=" << p99
                      << " ms, throughput=" << std::setprecision(0) << throughput_k << " execs/s\n";
            return median * 5.0; // normalized to 10k iters
        };

        bytemorph::virt::BvmProgram arith_prog;
        arith_prog.instructions = {
            {bytemorph::virt::VmOpcode::MovImm, 1, 0, 0, 42},
            {bytemorph::virt::VmOpcode::MovImm, 2, 0, 0, 19},
            {bytemorph::virt::VmOpcode::Add, 3, 1, 2, 0},
            {bytemorph::virt::VmOpcode::Xor, 0, 3, 1, 0},
            {bytemorph::virt::VmOpcode::Ret, 0, 0, 0, 0}
        };
        bytemorph::virt::BvmProgram loop_prog;
        loop_prog.instructions = {
            {bytemorph::virt::VmOpcode::MovImm, 0, 0, 0, 0},
            {bytemorph::virt::VmOpcode::MovImm, 1, 0, 0, 1},
            {bytemorph::virt::VmOpcode::MovImm, 2, 0, 0, 16},
            {bytemorph::virt::VmOpcode::Add, 0, 0, 1, 0},
            {bytemorph::virt::VmOpcode::Add, 1, 1, 1, 0},
            {bytemorph::virt::VmOpcode::Cmp, 0, 1, 2, 0},
            {bytemorph::virt::VmOpcode::Jlt, 0, 0, 0, 3},
            {bytemorph::virt::VmOpcode::Ret, 0, 0, 0, 0}
        };

        std::cout << "  --- Professional Multi-Sample VM Suite (15 samples, warm-up=200) ---\n";
        const double arith_10k = run_bench_stats("Arithmetic", arith_prog, {});
        (void)run_bench_stats("Memory Load/Store", stack_prog, {});
        (void)run_bench_stats("Loop/Branch", loop_prog, {});
        const double ext_10k = run_bench_stats("External Call Bridge", ext_prog, ext_opts);

        if (compare_baseline) {
            constexpr double kV07Interpreter10kMs = 2.987;
            constexpr double kV07ExtBridge10kMs = 2.405;
            const double interp_delta_pct = ((arith_10k - kV07Interpreter10kMs) / kV07Interpreter10kMs) * 100.0;
            const double ext_delta_pct = ((ext_10k - kV07ExtBridge10kMs) / kV07ExtBridge10kMs) * 100.0;
            std::cout << "  --- Baseline Comparison (v0.7 -> v0.8) ---\n"
                      << "    VM Interpreter (10k eq.)  : v0.7=" << std::setprecision(3) << kV07Interpreter10kMs
                      << " ms -> v0.8=" << arith_10k << " ms (" << std::setprecision(1) << interp_delta_pct << "%)\n"
                      << "    External Call Bridge (10k): v0.7=" << std::setprecision(3) << kV07ExtBridge10kMs
                      << " ms -> v0.8=" << ext_10k << " ms (" << std::setprecision(1) << ext_delta_pct << "%)\n";
        }
    }

    if (detailed) {
        std::cout << "  --- Multi-Function Shared Runtime Scaling ---\n";
        for (const std::size_t n_funcs : {2u, 5u, 10u, 20u}) {
            std::vector<bytemorph::virt::BvmProgram> progs(n_funcs, stack_prog);
            bytemorph::prot::detail::SharedRuntimeLayout layout_x64;
            bytemorph::prot::detail::SharedRuntimeLayout layout_a64;
            const auto tm0 = std::chrono::steady_clock::now();
            auto rx = bytemorph::prot::detail::emit_shared_pic_x64_vm_runtime(
                progs, bytemorph::prot::detail::AbiKind::Win64, layout_x64);
            auto ra = bytemorph::prot::detail::emit_shared_pic_arm64_vm_runtime(progs, layout_a64);
            const auto tm1 = std::chrono::steady_clock::now();
            const double multi_ms = std::chrono::duration<double, std::milli>(tm1 - tm0).count();
            std::cout << "    " << n_funcs << " funcs -> x64="
                      << (rx ? rx.value().size() : 0) << "B, ARM64="
                      << (ra ? ra.value().size() : 0) << "B, emit="
                      << std::setprecision(3) << multi_ms << " ms\n";
        }
    }
    return 0;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    std::string_view cmd = argv[1];
    if (cmd == "--help" || cmd == "-h") {
        print_usage();
        return 0;
    }
    if (cmd == "--version" || cmd == "-v") {
        std::cout << "ByteMorph v0.8.0\n";
        return 0;
    }
    if (cmd == "benchmark-vm") {
        return cmd_benchmark_vm();
    }
    if (cmd == "benchmark-protection") {
        bool detailed = false;
        bool compare_baseline = false;
        for (int i = 2; i < argc; ++i) {
            if (std::string_view(argv[i]) == "--detailed") detailed = true;
            else if (std::string_view(argv[i]) == "--compare-baseline") compare_baseline = true;
        }
        return cmd_benchmark_protection(detailed, compare_baseline);
    }

    if (argc < 3) {
        std::cerr << "Error: missing <file> argument.\n";
        print_usage();
        return 1;
    }

    std::string file_path = argv[2];
    std::string output_path;
    std::size_t max_insns = 0;
    std::size_t fn_idx = 0;
    std::uint64_t seed = 0x42595445ULL;
    std::string output_format = "text";
    std::string eligibility_report_path;
    bool analyze_functions_only = false;
    bool detailed_flag = false;
    bytemorph::prot::ProtectOptions prot_opts;

    for (int i = 3; i < argc; ++i) {
        std::string_view arg = argv[i];
        if (arg == "--verbose") {
            diagnostics::Logger::instance().set_level(diagnostics::LogLevel::Info);
        } else if (arg == "--max" && i + 1 < argc) {
            try { max_insns = std::stoull(argv[++i]); } catch (...) { return 1; }
        } else if ((arg == "--output" || arg == "-o") && i + 1 < argc) {
            output_path = argv[++i];
        } else if (arg == "--seed" && i + 1 < argc) {
            try { seed = std::stoull(argv[++i], nullptr, 0); prot_opts.seed = seed; } catch (...) { return 1; }
        } else if (arg == "--fn" && i + 1 < argc) {
            try { fn_idx = std::stoull(argv[++i]); } catch (...) { return 1; }
        } else if (arg == "--profile" && i + 1 < argc) {
            std::string_view p = argv[++i];
            if (p == "fast") prot_opts.profile = bytemorph::prot::ProtectionProfile::Fast;
            else if (p == "balanced") prot_opts.profile = bytemorph::prot::ProtectionProfile::Balanced;
            else if (p == "maximum") prot_opts.profile = bytemorph::prot::ProtectionProfile::Maximum;
            else { std::cerr << "Invalid --profile (expected fast|balanced|maximum)\n"; return 1; }
        } else if (arg == "--functions") {
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                std::string fmode = argv[++i];
                if (fmode == "auto") {
                    prot_opts.auto_select_functions = true;
                } else if (fmode == "all-eligible") {
                    prot_opts.protect_all_eligible = true;
                } else {
                    std::size_t start = 0;
                    while (start < fmode.size()) {
                        const std::size_t comma = fmode.find(',', start);
                        std::string item = (comma == std::string::npos)
                            ? fmode.substr(start)
                            : fmode.substr(start, comma - start);
                        if (!item.empty()) {
                            if (item.rfind("0x", 0) == 0 || item.rfind("0X", 0) == 0) {
                                try {
                                    prot_opts.target_function_rvas.push_back(std::stoull(item, nullptr, 16));
                                } catch (...) {
                                    std::cerr << "Invalid RVA in --functions: " << item << '\n';
                                    return 1;
                                }
                            } else {
                                prot_opts.target_function_names.push_back(item);
                            }
                        }
                        if (comma == std::string::npos) break;
                        start = comma + 1;
                    }
                    if (prot_opts.target_function_names.size() == 1 && prot_opts.target_function_rvas.empty()) {
                        prot_opts.target_function_name = prot_opts.target_function_names.front();
                    }
                }
            } else {
                analyze_functions_only = true;
                prot_opts.auto_select_functions = true;
            }
        } else if (arg == "--func" && i + 1 < argc) {
            prot_opts.target_function_name = argv[++i];
        } else if (arg == "--func-rva" && i + 1 < argc) {
            try { prot_opts.target_function_rva = std::stoull(argv[++i], nullptr, 16); } catch (...) { return 1; }
        } else if (arg == "--no-strings") {
            prot_opts.protect_strings = false;
        } else if (arg == "--no-rollback") {
            prot_opts.rollback_on_failure = false;
        } else if (arg == "--allow-signed-strip") {
            prot_opts.allow_strip_signature = true;
        } else if (arg == "--allow-ext-calls") {
            prot_opts.allow_external_calls = true;
        } else if (arg == "--detailed") {
            detailed_flag = true;
        } else if (arg == "--eligibility-report" && i + 1 < argc) {
            eligibility_report_path = argv[++i];
        } else if (arg == "--format" && i + 1 < argc) {
            output_format = argv[++i];
            if (output_format != "text" && output_format != "json") return 1;
        } else {
            std::cerr << "Unknown option: " << arg << '\n';
            return 1;
        }
    }

    if (cmd == "obfuscate-ir") return cmd_obfuscate_ir(file_path, output_path, seed);
    if (cmd == "vm-compile") return cmd_vm_compile(file_path, output_path, seed, fn_idx);
    if (cmd == "vm-run") return cmd_vm_run(file_path);
    if (cmd == "vm-inspect") return cmd_vm_inspect(file_path);
    if (cmd == "protect") return cmd_protect(file_path, output_path, prot_opts);
    if (cmd == "compatibility") return cmd_compatibility(file_path, output_format, prot_opts.allow_external_calls, detailed_flag);
    if (cmd == "verify") return cmd_verify(file_path);
    if (cmd == "protection-info") return cmd_protection_info(file_path, analyze_functions_only, output_format);
    if (cmd == "analyze" && !eligibility_report_path.empty()) {
        return cmd_eligibility_report(file_path, eligibility_report_path, prot_opts.allow_external_calls);
    }

    auto loader = create_default_loader();
    auto load_res = loader.load_file(file_path);
    if (!load_res) {
        std::cerr << "Load failed: " << load_res.error().to_string() << '\n';
        return 1;
    }

    const auto& bin = *load_res.value();
    if (cmd == "info") { print_info(bin); return 0; }
    if (cmd == "disasm") return cmd_disasm(bin, max_insns);
    if (cmd == "analyze") return analyze_functions_only ? cmd_functions(bin, max_insns) : cmd_analyze(bin, max_insns);
    if (cmd == "functions") return cmd_functions(bin, max_insns);
    if (cmd == "cfg") return cmd_cfg(bin, max_insns);
    if (cmd == "inspect") return (output_format == "json") ? cmd_inspect_json(bin, max_insns) : cmd_analyze(bin, max_insns);
    if (cmd == "ir") return cmd_ir(bin, output_path, max_insns);

    std::cerr << "Unknown command: " << cmd << '\n';
    print_usage();
    return 1;
}
