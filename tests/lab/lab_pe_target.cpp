#include <cstdint>
#include <cstdlib>
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

int main(int argc, char* argv[]) {
    std::int64_t a = 42;
    std::int64_t b = 19;
    if (argc >= 3) {
        a = std::strtoll(argv[1], nullptr, 10);
        b = std::strtoll(argv[2], nullptr, 10);
    }
    const std::int64_t res = bm_target_compute(a, b);
    std::cout << "RESULT=" << res << '\n';
    return 0;
}
