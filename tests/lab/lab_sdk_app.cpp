#include <bytemorph/protect.hpp>

#include <cstdint>
#include <cstdio>

extern "C" {

BYTEMORPH_PROTECT_BEGIN
BYTEMORPH_NOINLINE int calculate_license(int value) {
    int acc = value * 42;
    acc ^= 0x5A5A;
    return acc + 17;
}
BYTEMORPH_PROTECT_END

BYTEMORPH_PROTECT_FUNC
std::uint64_t sdk_mix_token(std::uint64_t a, std::uint64_t b) {
    std::uint64_t x = (a * 1315423911ULL) ^ (b + 0x9E3779B9ULL);
    return x + (a << 3) - (b >> 2);
}

} // extern "C"

int main(int argc, char** argv) {
    const int base = (argc > 1) ? std::atoi(argv[1]) : 19;
    const int lic = calculate_license(base);
    const std::uint64_t tok = sdk_mix_token(static_cast<std::uint64_t>(base), static_cast<std::uint64_t>(lic));
    std::printf("SDK ver=%s lic=%d tok=%llu\n",
                bytemorph::sdk::version().data(),
                lic,
                static_cast<unsigned long long>(tok));
    return (lic != 0 && tok != 0) ? 0 : 1;
}
