#include "bytemorph/core/diagnostics/error.hpp"

#include <sstream>

namespace bytemorph::core::diagnostics {

std::string_view error_code_name(ErrorCode code) noexcept {
    switch (code) {
        case ErrorCode::None: return "None";
        case ErrorCode::IoError: return "IoError";
        case ErrorCode::FileNotFound: return "FileNotFound";
        case ErrorCode::EmptyInput: return "EmptyInput";
        case ErrorCode::TruncatedData: return "TruncatedData";
        case ErrorCode::InvalidMagic: return "InvalidMagic";
        case ErrorCode::UnsupportedFormat: return "UnsupportedFormat";
        case ErrorCode::UnsupportedArchitecture: return "UnsupportedArchitecture";
        case ErrorCode::ParseError: return "ParseError";
        case ErrorCode::DisassemblyError: return "DisassemblyError";
        case ErrorCode::OutOfBounds: return "OutOfBounds";
        case ErrorCode::IntegerOverflow: return "IntegerOverflow";
        case ErrorCode::InternalError: return "InternalError";
        case ErrorCode::NotImplemented: return "NotImplemented";
    }
    return "Unknown";
}

std::string Error::to_string() const {
    std::ostringstream oss;
    oss << "[" << error_code_name(code) << "]";
    if (!context.empty()) {
        oss << " (" << context << ")";
    }
    if (!message.empty()) {
        oss << " " << message;
    }
    return oss.str();
}

} // namespace bytemorph::core::diagnostics
