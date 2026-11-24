#include "lab_c_lib.h"

static int64_t g_lab_c_state = 0x10203040LL;

uint64_t lab_c_fnv1a(const uint8_t* data, size_t len) {
    uint64_t h = 14695981039346656037ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= (uint64_t)data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

int64_t lab_c_transform_record(LabRecord* rec, int64_t bias) {
    if (!rec) return -1;
    rec->x = (rec->x * 3) ^ bias;
    rec->y = (rec->y + rec->x) - (bias >> 1);
    return rec->x + rec->y + (int64_t)rec->id;
}

int64_t lab_c_sum_array(const int64_t* arr, size_t count) {
    int64_t total = 0;
    for (size_t i = 0; i < count; ++i) {
        total += (arr[i] ^ (int64_t)i);
    }
    return total;
}

double lab_c_weighted_score(double a, double b, int64_t scale) {
    return (a * 1.25 + b * 0.75) * (double)scale;
}

int64_t lab_c_global_step(int64_t delta) {
    g_lab_c_state = (g_lab_c_state + delta) ^ 0x5A5A5A5ALL;
    return g_lab_c_state;
}
