#include "bytemorph/virt/asmjit_prototype.hpp"
#include "bytemorph/virt/bvm_format.hpp"
#include "bytemorph/virt/vm_interpreter.hpp"

#include <chrono>

#if defined(BYTEMORPH_HAS_ASMJIT) && (defined(_M_X64) || defined(__x86_64__))
#include <asmjit/x86.h>
#endif

namespace bytemorph::virt {

core::diagnostics::Result<AsmJitBenchResult>
AsmJitPrototype::run_arithmetic_comparison(std::uint64_t a, std::uint64_t b, int iterations) {
    AsmJitBenchResult out;

    // Build equivalent VM program: R0 = ((a + b) ^ (a - b)) + (a * 3)
    BvmProgram prog;
    prog.instructions = {
        {VmOpcode::Add, 2, 0, 1, 0},       // R2 = R0 + R1
        {VmOpcode::Sub, 3, 0, 1, 0},       // R3 = R0 - R1
        {VmOpcode::Xor, 2, 2, 3, 0},       // R2 = R2 ^ R3
        {VmOpcode::MovImm, 4, 0, 0, 3},    // R4 = 3
        {VmOpcode::Mul, 5, 0, 4, 0},       // R5 = R0 * 3
        {VmOpcode::Add, 0, 2, 5, 0},       // R0 = R2 + R5
        {VmOpcode::Ret, 0, 0, 0, 0}
    };

    VmExecOptions opts;
    opts.initial_regs[0] = a;
    opts.initial_regs[1] = b;

    const auto vm_t0 = std::chrono::steady_clock::now();
    std::uint64_t vm_res = 0;
    for (int i = 0; i < iterations; ++i) {
        auto r = VmInterpreter::execute(prog, opts);
        if (!r) {
            return core::diagnostics::Result<AsmJitBenchResult>::err(
                r.error().code, r.error().message, r.error().context);
        }
        vm_res = r.value().return_value;
    }
    const auto vm_t1 = std::chrono::steady_clock::now();
    out.vm_result = vm_res;
    out.vm_ms = std::chrono::duration<double, std::milli>(vm_t1 - vm_t0).count();

#if defined(BYTEMORPH_HAS_ASMJIT) && (defined(_M_X64) || defined(__x86_64__))
    using FnType = std::uint64_t(*)(std::uint64_t, std::uint64_t);

    asmjit::JitRuntime rt;
    asmjit::CodeHolder code;
    code.init(rt.environment(), rt.cpu_features());
    asmjit::x86::Assembler assm(&code);

#if defined(_WIN32)
    // Win64 ABI: rcx = a, rdx = b
    assm.lea(asmjit::x86::rax, asmjit::x86::ptr(asmjit::x86::rcx, asmjit::x86::rdx)); // rax = a + b
    assm.mov(asmjit::x86::r8, asmjit::x86::rcx);
    assm.sub(asmjit::x86::r8, asmjit::x86::rdx);                                      // r8 = a - b
    assm.xor_(asmjit::x86::rax, asmjit::x86::r8);                                     // rax = (a+b) ^ (a-b)
    assm.imul(asmjit::x86::r9, asmjit::x86::rcx, 3);                                  // r9 = a * 3
    assm.add(asmjit::x86::rax, asmjit::x86::r9);                                      // rax += a * 3
    assm.ret();
#else
    // SysV AMD64 ABI: rdi = a, rsi = b
    assm.lea(asmjit::x86::rax, asmjit::x86::ptr(asmjit::x86::rdi, asmjit::x86::rsi));
    assm.mov(asmjit::x86::r8, asmjit::x86::rdi);
    assm.sub(asmjit::x86::r8, asmjit::x86::rsi);
    assm.xor_(asmjit::x86::rax, asmjit::x86::r8);
    assm.imul(asmjit::x86::r9, asmjit::x86::rdi, 3);
    assm.add(asmjit::x86::rax, asmjit::x86::r9);
    assm.ret();
#endif

    FnType fn = nullptr;
    const auto err = rt.add(&fn, &code);
    if (err != asmjit::kErrorOk || !fn) {
        return core::diagnostics::Result<AsmJitBenchResult>::err(
            core::diagnostics::ErrorCode::InternalError,
            "AsmJit failed to emit native x86-64 prototype",
            "AsmJitPrototype::run_arithmetic_comparison");
    }

    const auto nat_t0 = std::chrono::steady_clock::now();
    volatile std::uint64_t nat_res = 0;
    for (int i = 0; i < iterations; ++i) {
        nat_res = fn(a, b);
    }
    const auto nat_t1 = std::chrono::steady_clock::now();

    out.native_result = nat_res;
    out.native_ms = std::chrono::duration<double, std::milli>(nat_t1 - nat_t0).count();
    out.available = true;
    rt.release(fn);
#endif

    return out;
}

} // namespace bytemorph::virt
