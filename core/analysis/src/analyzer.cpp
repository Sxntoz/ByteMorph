#include "bytemorph/core/analysis/analyzer.hpp"

#include <algorithm>
#include <map>
#include <queue>
#include <set>
#include <sstream>

namespace bytemorph::core::analysis {

namespace {

[[nodiscard]] std::string format_va_name(std::string_view prefix, std::uint64_t va) {
    std::ostringstream oss;
    oss << prefix << "_0x" << std::hex << va;
    return oss.str();
}

[[nodiscard]] bool is_block_terminator(ControlFlowKind flow) noexcept {
    return flow == ControlFlowKind::UnconditionalJump ||
           flow == ControlFlowKind::ConditionalJump ||
           flow == ControlFlowKind::Return ||
           flow == ControlFlowKind::Halt;
}

void detect_loops_dfs(std::uint64_t node,
                      const std::map<std::uint64_t, BasicBlock>& blocks,
                      std::map<std::uint64_t, int>& color,
                      std::set<std::uint64_t>& loop_headers) {
    color[node] = 1; // gray (in current DFS stack)
    auto it = blocks.find(node);
    if (it != blocks.end()) {
        for (const auto succ : it->second.successors) {
            const int c = color[succ];
            if (c == 1) {
                loop_headers.insert(succ);
            } else if (c == 0 && blocks.contains(succ)) {
                detect_loops_dfs(succ, blocks, color, loop_headers);
            }
        }
    }
    color[node] = 2; // black (done)
}

} // namespace

diagnostics::Result<AnalysisResult>
BinaryAnalyzer::analyze(const binary::IBinaryFile& binary,
                        const IDisassemblerEngine& disasm,
                        const Options& options) const {
    using diagnostics::ErrorCode;

    if (binary.info().architecture != disasm.architecture()) {
        return diagnostics::Result<AnalysisResult>::err(
            ErrorCode::UnsupportedArchitecture,
            "Disassembler architecture does not match binary architecture",
            "BinaryAnalyzer::analyze");
    }

    AnalysisResult result;

    result.limitations.push_back({
        "Indirect Control Flow",
        "Indirect jumps/calls (jump tables, function pointers, virtual calls) are recorded but targets are not speculated."
    });
    result.limitations.push_back({
        "Stripped Binaries & Data-in-Code",
        "Without symbols or unwind metadata (.pdata/.eh_frame_hdr/LC_FUNCTION_STARTS), function discovery relies on entry point and direct call targets."
    });
    result.limitations.push_back({
        "Obfuscated / Packed Code",
        "Self-modifying, encrypted, or packed sections are not unpacked in read-only v0.2 analysis."
    });

    std::vector<const binary::SectionInfo*> exec_sections;
    for (const auto& sec : binary.sections()) {
        if (sec.executable && sec.raw_size > 0) {
            exec_sections.push_back(&sec);
        }
    }

    if (exec_sections.empty()) {
        result.limitations.push_back({
            "Executable Sections",
            "No executable sections with raw data found in binary."
        });
        result.overall_confidence = AnalysisConfidence::Low;
        return result;
    }

    std::map<std::uint64_t, DisassembledInstruction> insn_map;
    for (const auto* sec : exec_sections) {
        const auto slice_res = binary.read_virtual(sec->virtual_address, static_cast<std::size_t>(sec->raw_size));
        if (!slice_res) {
            result.limitations.push_back({
                "Section Read",
                "Skipped section '" + sec->name + "': " + slice_res.error().message
            });
            continue;
        }

        auto dis_res = disasm.disassemble(slice_res.value(), sec->virtual_address, options.max_instructions_per_section);
        if (!dis_res) {
            result.limitations.push_back({
                "Disassembly",
                "Partial/failed disassembly in section '" + sec->name + "': " + dis_res.error().message
            });
            continue;
        }

        for (auto& insn : dis_res.value()) {
            result.total_instructions++;
            insn_map.emplace(insn.address, std::move(insn));
        }
    }

    if (insn_map.empty()) {
        result.overall_confidence = AnalysisConfidence::Low;
        return result;
    }

    struct Seed {
        std::string name;
        std::uint64_t va{0};
        std::optional<std::uint64_t> end_va;
        bool from_sym{false};
        bool from_ep{false};
        bool from_call{false};
        bool from_unwind{false};
        std::string source;
    };

    std::map<std::uint64_t, Seed> seeds;

    if (binary.info().entry_point != 0 && insn_map.contains(binary.info().entry_point)) {
        seeds[binary.info().entry_point] = Seed{
            "_start", binary.info().entry_point, std::nullopt, false, true, false, false, "entry_point"
        };
    }

    for (const auto& hint : binary.info().function_hints) {
        if (hint.start_va != 0 && insn_map.contains(hint.start_va)) {
            auto& s = seeds[hint.start_va];
            s.va = hint.start_va;
            s.from_unwind = true;
            if (hint.end_va > hint.start_va) {
                s.end_va = hint.end_va;
            }
            if (s.source.empty()) {
                s.source = hint.source;
            }
            if (s.name.empty()) {
                s.name = format_va_name("sub", hint.start_va);
            }
        }
    }

    for (const auto& sym : binary.symbols()) {
        if (sym.is_function && sym.address != 0 && insn_map.contains(sym.address)) {
            auto& s = seeds[sym.address];
            s.va = sym.address;
            s.from_sym = true;
            if (sym.size > 0 && (!s.end_va.has_value() || sym.address + sym.size < *s.end_va)) {
                s.end_va = sym.address + sym.size;
            }
            if (s.source.empty()) {
                s.source = "symbol";
            }
            if (!sym.name.empty()) {
                s.name = sym.name;
            } else if (s.name.empty()) {
                s.name = format_va_name("sub", sym.address);
            }
        }
    }

    for (const auto& exp : binary.exports()) {
        if (!exp.is_forwarded && exp.address != 0 && insn_map.contains(exp.address)) {
            auto& s = seeds[exp.address];
            s.va = exp.address;
            s.from_sym = true;
            if (s.source.empty()) {
                s.source = "export";
            }
            if (!exp.name.empty() && s.name.empty()) {
                s.name = exp.name;
            }
        }
    }

    for (const auto& [va, insn] : insn_map) {
        if (insn.flow == ControlFlowKind::Call && insn.branch_target.has_value()) {
            const std::uint64_t target = *insn.branch_target;
            if (insn_map.contains(target) && !seeds.contains(target)) {
                seeds[target] = Seed{
                    format_va_name("sub", target), target, std::nullopt, false, false, true, false, "call_target"
                };
            }
        }
    }

    std::size_t fn_count = 0;
    for (const auto& [entry_va, seed] : seeds) {
        if (fn_count >= options.max_functions) {
            result.limitations.push_back({
                "Function Limit",
                "Reached maximum function analysis limit (" + std::to_string(options.max_functions) + ")."
            });
            break;
        }
        ++fn_count;

        FunctionInfo fn;
        fn.name = seed.name.empty() ? format_va_name("sub", entry_va) : seed.name;
        fn.entry_va = entry_va;
        fn.metadata_end_va = seed.end_va;
        fn.from_symbol = seed.from_sym;
        fn.from_entry_point = seed.from_ep;
        fn.from_call_target = seed.from_call;
        fn.from_unwind_metadata = seed.from_unwind;
        fn.discovery_source = seed.source;

        auto in_fn_bounds = [&](std::uint64_t va) -> bool {
            if (!fn.metadata_end_va) {
                return true;
            }
            return va >= entry_va && va < *fn.metadata_end_va;
        };

        std::set<std::uint64_t> block_starts;
        std::set<std::uint64_t> visited;
        std::queue<std::uint64_t> worklist;
        block_starts.insert(entry_va);
        worklist.push(entry_va);

        while (!worklist.empty()) {
            std::uint64_t cur = worklist.front();
            worklist.pop();
            if (!insn_map.contains(cur) || !in_fn_bounds(cur) || visited.contains(cur)) {
                continue;
            }

            while (insn_map.contains(cur) && in_fn_bounds(cur) && !visited.contains(cur)) {
                visited.insert(cur);
                const auto& insn = insn_map.at(cur);
                const std::uint64_t next_va = cur + insn.bytes.size();

                if (insn.flow == ControlFlowKind::UnconditionalJump) {
                    if (insn.branch_target && insn_map.contains(*insn.branch_target) && in_fn_bounds(*insn.branch_target)) {
                        block_starts.insert(*insn.branch_target);
                        worklist.push(*insn.branch_target);
                    }
                    break;
                }
                if (insn.flow == ControlFlowKind::ConditionalJump) {
                    if (insn.branch_target && insn_map.contains(*insn.branch_target) && in_fn_bounds(*insn.branch_target)) {
                        block_starts.insert(*insn.branch_target);
                        worklist.push(*insn.branch_target);
                    }
                    if (insn_map.contains(next_va) && in_fn_bounds(next_va)) {
                        block_starts.insert(next_va);
                        worklist.push(next_va);
                    }
                    break;
                }
                if (insn.flow == ControlFlowKind::Return || insn.flow == ControlFlowKind::Halt) {
                    break;
                }

                cur = next_va;
            }
        }

        // If metadata_end_va is known, check for unreachable instructions inside [entry_va, metadata_end_va)
        if (fn.metadata_end_va) {
            auto it = insn_map.lower_bound(entry_va);
            while (it != insn_map.end() && it->first < *fn.metadata_end_va) {
                if (!visited.contains(it->first)) {
                    block_starts.insert(it->first);
                }
                ++it;
            }
        }

        std::map<std::uint64_t, BasicBlock> blocks_by_start;
        bool has_invalid_insn = false;

        for (const std::uint64_t bstart : block_starts) {
            if (!insn_map.contains(bstart)) {
                continue;
            }
            BasicBlock bb;
            bb.start_va = bstart;
            bb.is_unreachable = !visited.contains(bstart);
            std::uint64_t cur = bstart;

            while (insn_map.contains(cur) && in_fn_bounds(cur)) {
                if (cur != bstart && block_starts.contains(cur)) {
                    bb.successors.push_back(cur);
                    break;
                }
                const auto& insn = insn_map.at(cur);
                bb.instructions.push_back(insn);
                const std::uint64_t next_va = cur + insn.bytes.size();
                bb.end_va = next_va;
                fn.size_bytes += insn.bytes.size();

                if (insn.mnemonic == "db" || insn.mnemonic == "dcd") {
                    bb.has_invalid_instruction = true;
                    has_invalid_insn = true;
                }
                if (insn.is_indirect) {
                    if (insn.flow == ControlFlowKind::Call) {
                        fn.indirect_call_count++;
                    } else if (insn.flow == ControlFlowKind::UnconditionalJump) {
                        bb.has_indirect_branch = true;
                        fn.indirect_jump_count++;
                    }
                    result.total_indirect_branches++;
                }

                if (insn.flow == ControlFlowKind::UnconditionalJump) {
                    if (insn.branch_target && block_starts.contains(*insn.branch_target)) {
                        bb.successors.push_back(*insn.branch_target);
                    }
                    break;
                }
                if (insn.flow == ControlFlowKind::ConditionalJump) {
                    if (insn.branch_target && block_starts.contains(*insn.branch_target)) {
                        bb.successors.push_back(*insn.branch_target);
                    }
                    if (block_starts.contains(next_va) && in_fn_bounds(next_va)) {
                        bb.successors.push_back(next_va);
                    }
                    break;
                }
                if (is_block_terminator(insn.flow)) {
                    break;
                }
                cur = next_va;
            }
            blocks_by_start.emplace(bstart, std::move(bb));
        }

        // Predecessors
        for (const auto& [bstart, bb] : blocks_by_start) {
            for (const auto succ : bb.successors) {
                auto it = blocks_by_start.find(succ);
                if (it != blocks_by_start.end()) {
                    it->second.predecessors.push_back(bstart);
                }
            }
        }

        // Loop detection via DFS back-edges
        std::map<std::uint64_t, int> color;
        std::set<std::uint64_t> loop_headers;
        detect_loops_dfs(entry_va, blocks_by_start, color, loop_headers);
        for (const auto lh : loop_headers) {
            auto it = blocks_by_start.find(lh);
            if (it != blocks_by_start.end()) {
                it->second.is_loop_header = true;
            }
        }
        fn.loop_count = loop_headers.size();
        result.total_loops += fn.loop_count;

        for (auto& [_, bb] : blocks_by_start) {
            if (bb.is_unreachable) {
                fn.unreachable_block_count++;
                result.total_unreachable_blocks++;
            }
            fn.blocks.push_back(std::move(bb));
        }

        // Confidence assessment
        if (has_invalid_insn || fn.indirect_jump_count > 0) {
            fn.confidence = AnalysisConfidence::Low;
        } else if (fn.from_symbol || fn.from_unwind_metadata || fn.from_entry_point) {
            fn.confidence = AnalysisConfidence::High;
        } else {
            fn.confidence = AnalysisConfidence::Medium;
        }

        result.functions.push_back(std::move(fn));
    }

    // Detect overlapping functions
    for (std::size_t i = 0; i + 1 < result.functions.size(); ++i) {
        auto& cur = result.functions[i];
        auto& nxt = result.functions[i + 1];
        if (cur.entry_va + cur.size_bytes > nxt.entry_va) {
            cur.overlaps_another_function = true;
            nxt.overlaps_another_function = true;
        }
    }

    // Overall confidence
    std::size_t high_cnt = 0;
    std::size_t low_cnt = 0;
    for (const auto& fn : result.functions) {
        if (fn.confidence == AnalysisConfidence::High) ++high_cnt;
        else if (fn.confidence == AnalysisConfidence::Low) ++low_cnt;
    }
    if (result.functions.empty() || low_cnt > high_cnt) {
        result.overall_confidence = AnalysisConfidence::Low;
    } else if (high_cnt >= result.functions.size() / 2 && result.total_indirect_branches == 0) {
        result.overall_confidence = AnalysisConfidence::High;
    } else {
        result.overall_confidence = AnalysisConfidence::Medium;
    }

    return result;
}

} // namespace bytemorph::core::analysis
