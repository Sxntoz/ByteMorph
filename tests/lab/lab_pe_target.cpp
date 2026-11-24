#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

#if defined(_MSC_VER)
#define BM_EXPORT __declspec(dllexport) __declspec(noinline)
#else
#define BM_EXPORT __attribute__((visibility("default"), noinline))
#endif

extern "C" BM_EXPORT std::int64_t bm_target_compute(std::int64_t a, std::int64_t b) {
    const std::int64_t sum = a + b;
    const std::int64_t diff = a - b;
    const std::int64_t mix = sum ^ diff;
    return mix + (a * 3);
}

extern "C" BM_EXPORT std::int64_t bm_target_multi_args(std::int64_t a, std::int64_t b, std::int64_t c, std::int64_t d) {
    return (a * 2) + (b * 3) - c + (d ^ a);
}

extern "C" BM_EXPORT std::int64_t bm_target_branch_loop(std::int64_t a, std::int64_t b) {
    if (a <= 0) {
        return b;
    }
    std::int64_t acc = b;
    for (std::int64_t i = 1; i <= 4; ++i) {
        acc += (a ^ i);
    }
    return acc;
}

extern "C" BM_EXPORT std::int64_t bm_target_helper(std::int64_t x) {
    return (x * 5) + 17;
}

extern "C" BM_EXPORT std::int64_t bm_target_caller(std::int64_t a, std::int64_t b) {
    const std::int64_t c = bm_target_compute(a, b);
    const std::int64_t h = bm_target_helper(b);
    return c + h;
}

alignas(8) static const std::int64_t g_bm_ro_bias = 0x1337LL;
alignas(8) static std::int64_t g_bm_rw_counter = 100LL;

extern "C" BM_EXPORT std::int64_t bm_target_global_rw(std::int64_t a) {
    g_bm_rw_counter += a;
    return g_bm_rw_counter + g_bm_ro_bias;
}

extern "C" BM_EXPORT std::int64_t bm_target_cmov_select(std::int64_t a, std::int64_t b) {
    return (a > b) ? (a * 3 + 7) : (b * 2 - 5);
}

extern "C" BM_EXPORT std::int64_t bm_target_unsigned_cmp(std::uint64_t a, std::uint64_t b) {
    return (a < b) ? 11LL : 29LL;
}

int main(int argc, char* argv[]) {
    std::int64_t a = 42;
    std::int64_t b = 19;
    if (argc >= 3) {
        a = std::strtoll(argv[1], nullptr, 10);
        b = std::strtoll(argv[2], nullptr, 10);
    }
    const std::int64_t res = bm_target_compute(a, b);
    if (argc >= 4 && std::strcmp(argv[3], "--v06") == 0) {
        const std::int64_t multi = bm_target_multi_args(a, b, a + 5, b + 3);
        const std::int64_t loop = bm_target_branch_loop(a, b);
        std::cout << "RESULT=" << res << " MULTI=" << multi << " LOOP=" << loop << '\n';
        return 0;
    }
    if (argc >= 4 && std::strcmp(argv[3], "--v07") == 0) {
        const std::int64_t multi = bm_target_multi_args(a, b, a + 5, b + 3);
        const std::int64_t loop = bm_target_branch_loop(a, b);
        const std::int64_t caller = bm_target_caller(a, b);
        std::cout << "RESULT=" << res << " MULTI=" << multi
                  << " LOOP=" << loop << " CALLER=" << caller << '\n';
        return 0;
    }
    if (argc >= 4 && std::strcmp(argv[3], "--v09") == 0) {
        const std::int64_t g1 = bm_target_global_rw(a);
        const std::int64_t g2 = bm_target_global_rw(b);
        const std::int64_t cm = bm_target_cmov_select(a, b);
        const std::int64_t uc = bm_target_unsigned_cmp(static_cast<std::uint64_t>(a), static_cast<std::uint64_t>(b));
        std::cout << "RESULT=" << res << " GLOBAL1=" << g1 << " GLOBAL2=" << g2
                  << " CMOV=" << cm << " UCMP=" << uc << '\n';
        return 0;
    }
    std::cout << "RESULT=" << res << '\n';
    return 0;
}
