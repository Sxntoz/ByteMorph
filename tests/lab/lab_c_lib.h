#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_MSC_VER)
#define LAB_EXPORT __declspec(dllexport) __declspec(noinline)
#else
#define LAB_EXPORT __attribute__((visibility("default"), noinline))
#endif

typedef struct LabRecord {
    uint64_t id;
    int64_t  x;
    int64_t  y;
    double   weight;
} LabRecord;

LAB_EXPORT uint64_t lab_c_fnv1a(const uint8_t* data, size_t len);
LAB_EXPORT int64_t  lab_c_transform_record(LabRecord* rec, int64_t bias);
LAB_EXPORT int64_t  lab_c_sum_array(const int64_t* arr, size_t count);
LAB_EXPORT double   lab_c_weighted_score(double a, double b, int64_t scale);
LAB_EXPORT int64_t  lab_c_global_step(int64_t delta);

#ifdef __cplusplus
}
#endif
