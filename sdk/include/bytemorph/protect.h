#ifndef BYTEMORPH_SDK_PROTECT_H
#define BYTEMORPH_SDK_PROTECT_H

#define BYTEMORPH_SDK_VERSION_MAJOR 0
#define BYTEMORPH_SDK_VERSION_MINOR 12
#define BYTEMORPH_SDK_VERSION_PATCH 0
#define BYTEMORPH_SDK_VERSION_STRING "0.12.0"

#if defined(_MSC_VER) && !defined(__clang__)
  #define BYTEMORPH_NOINLINE __declspec(noinline)
  #define BYTEMORPH_PROTECT_BEGIN __pragma(code_seg(push, ".bmprot"))
  #define BYTEMORPH_PROTECT_END __pragma(code_seg(pop))
  #define BYTEMORPH_PROTECT_FUNC __declspec(noinline)
#elif defined(__APPLE__)
  #define BYTEMORPH_NOINLINE __attribute__((noinline))
  #define BYTEMORPH_PROTECT_FUNC __attribute__((section("__TEXT,__bmprot"), noinline, used))
  #define BYTEMORPH_PROTECT_BEGIN \
      __attribute__((used, noinline)) static void __bm_sdk_begin_marker(void) {}
  #define BYTEMORPH_PROTECT_END \
      __attribute__((used, noinline)) static void __bm_sdk_end_marker(void) {}
#elif defined(__GNUC__) || defined(__clang__)
  #define BYTEMORPH_NOINLINE __attribute__((noinline))
  #define BYTEMORPH_PROTECT_FUNC __attribute__((section(".bmprot"), noinline, used))
  #define BYTEMORPH_PROTECT_BEGIN \
      __attribute__((used, noinline)) static void __bm_sdk_begin_marker(void) {}
  #define BYTEMORPH_PROTECT_END \
      __attribute__((used, noinline)) static void __bm_sdk_end_marker(void) {}
#else
  #define BYTEMORPH_NOINLINE
  #define BYTEMORPH_PROTECT_FUNC
  #define BYTEMORPH_PROTECT_BEGIN
  #define BYTEMORPH_PROTECT_END
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum bytemorph_profile_t {
    BYTEMORPH_PROFILE_FAST = 0,
    BYTEMORPH_PROFILE_BALANCED = 1,
    BYTEMORPH_PROFILE_MAXIMUM = 2
} bytemorph_profile_t;

static inline const char* bytemorph_sdk_version(void) {
    return BYTEMORPH_SDK_VERSION_STRING;
}

#ifdef __cplusplus
}
#endif

#endif /* BYTEMORPH_SDK_PROTECT_H */
