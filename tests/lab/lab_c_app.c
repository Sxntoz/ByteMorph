#include "lab_c_lib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[]) {
    int64_t seed = 17;
    const char* out_path = NULL;
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
            seed = strtoll(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--out") == 0 && i + 1 < argc) {
            out_path = argv[++i];
        }
    }

    size_t n = 16;
    int64_t* arr = (int64_t*)calloc(n, sizeof(int64_t));
    if (!arr) return 2;
    for (size_t i = 0; i < n; ++i) {
        arr[i] = seed + (int64_t)(i * 7);
    }

    LabRecord rec;
    rec.id = 42;
    rec.x = seed + 5;
    rec.y = seed * 2;
    rec.weight = 1.5;

    const int64_t t_res = lab_c_transform_record(&rec, 13);
    const int64_t s_res = lab_c_sum_array(arr, n);
    const double w_res = lab_c_weighted_score(12.5, 7.5, 4);
    const int64_t g_res = lab_c_global_step(seed);
    const uint64_t hash = lab_c_fnv1a((const uint8_t*)arr, n * sizeof(int64_t));

    free(arr);

    if (out_path) {
        FILE* f = fopen(out_path, "wb");
        if (!f) return 3;
        fprintf(f, "T=%lld S=%lld W=%.2f G=%lld H=%llu\n",
                (long long)t_res, (long long)s_res, w_res, (long long)g_res, (unsigned long long)hash);
        fclose(f);
    }

    printf("C_LAB T=%lld S=%lld W=%.2f G=%lld H=%llu\n",
           (long long)t_res, (long long)s_res, w_res, (long long)g_res, (unsigned long long)hash);
    return 0;
}
