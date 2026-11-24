#include "lab_c_lib.h"

#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#if defined(_MSC_VER)
#define LAB_NOINLINE __declspec(noinline)
#else
#define LAB_NOINLINE __attribute__((noinline))
#endif

// Generate 120 distinct non-inlined functions so binary analysis sees a multi-hundred-function executable
template <int N>
LAB_NOINLINE std::int64_t lab_poly_stage(std::int64_t x) {
    return ((x ^ static_cast<std::int64_t>(N)) + (N * 3LL)) * 5LL;
}

template <int... Is>
std::int64_t run_poly_bank(std::int64_t x, std::integer_sequence<int, Is...>) {
    std::int64_t acc = 0;
    ((acc ^= lab_poly_stage<Is>(x + Is)), ...);
    return acc;
}

extern "C" LAB_EXPORT std::int64_t lab_cpp_worker_fn(std::int64_t a, std::int64_t b) {
    std::int64_t acc = a ^ b;
    for (std::int64_t i = 0; i < 6; ++i) {
        acc = (acc * 3) + (i ^ a) - (b & 7);
    }
    return acc;
}

extern "C" LAB_EXPORT double lab_cpp_simd_mix(double a, double b, std::int64_t k) {
    const double kd = static_cast<double>(k);
    return (a * 2.5 + b) / (kd > 0.0 ? kd : 1.0);
}

extern "C" LAB_EXPORT std::int64_t lab_cpp_eh_fn(std::int64_t x) {
    try {
        if (x < 0) throw 101;
        return x * 2 + 1;
    } catch (...) {
        return -77;
    }
}

int main(int argc, char* argv[]) {
    std::int64_t seed = 23;
    std::string out_path;
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            seed = std::strtoll(argv[++i], nullptr, 10);
        } else if (std::strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        }
    }

    // 1. Call 120 distinct template functions
    const std::int64_t bank = run_poly_bank(seed, std::make_integer_sequence<int, 120>{});

    // 2. Dynamic allocation + C library calls
    std::vector<std::int64_t> vec(32);
    for (std::size_t i = 0; i < vec.size(); ++i) {
        vec[i] = seed + static_cast<std::int64_t>(i * 11);
    }
    const std::int64_t c_sum = lab_c_sum_array(vec.data(), vec.size());

    // 3. Multithreading calling protected worker
    std::mutex mtx;
    std::int64_t mt_acc = 0;
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&, t]() {
            const std::int64_t v = lab_cpp_worker_fn(seed + t, 19 + t);
            std::lock_guard<std::mutex> lk(mtx);
            mt_acc += v;
        });
    }
    for (auto& th : threads) th.join();

    // 4. SIMD/FP + EH check
    const double simd_v = lab_cpp_simd_mix(14.5, 5.5, 4);
    const std::int64_t eh_v = lab_cpp_eh_fn(-5);

    if (!out_path.empty()) {
        std::ofstream ofs(out_path, std::ios::binary);
        if (!ofs) return 3;
        ofs << "BANK=" << bank << " CSUM=" << c_sum << " MT=" << mt_acc
            << " SIMD=" << simd_v << " EH=" << eh_v << "\n";
    }

    std::cout << "CPP_LAB BANK=" << bank << " CSUM=" << c_sum << " MT=" << mt_acc
              << " SIMD=" << simd_v << " EH=" << eh_v << "\n";
    return 0;
}
