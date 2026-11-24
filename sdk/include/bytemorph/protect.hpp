#pragma once

#include "bytemorph/protect.h"

#include <cstdint>
#include <string_view>

namespace bytemorph::sdk {

inline constexpr std::uint32_t kVersionMajor = BYTEMORPH_SDK_VERSION_MAJOR;
inline constexpr std::uint32_t kVersionMinor = BYTEMORPH_SDK_VERSION_MINOR;
inline constexpr std::uint32_t kVersionPatch = BYTEMORPH_SDK_VERSION_PATCH;

enum class Profile : std::uint8_t {
    Fast = BYTEMORPH_PROFILE_FAST,
    Balanced = BYTEMORPH_PROFILE_BALANCED,
    Maximum = BYTEMORPH_PROFILE_MAXIMUM
};

[[nodiscard]] constexpr std::string_view version() noexcept {
    return BYTEMORPH_SDK_VERSION_STRING;
}

} // namespace bytemorph::sdk
