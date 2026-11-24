#include <cstdint>

#if defined(_WIN32)
  #define BM_LAB_EXPORT __declspec(dllexport)
#else
  #define BM_LAB_EXPORT __attribute__((visibility("default")))
#endif

extern "C" {

BM_LAB_EXPORT int bm_shared_add_mul(int a, int b) {
    int t = a * 7 + b * 13;
    return t ^ 0x1357;
}

BM_LAB_EXPORT std::uint64_t bm_shared_checksum(std::uint64_t seed, std::uint64_t count) {
    std::uint64_t h = seed ^ 0xCAFEBABEULL;
    for (std::uint64_t i = 0; i < count; ++i) {
        h = (h * 33ULL) + i;
    }
    return h;
}

} // extern "C"
