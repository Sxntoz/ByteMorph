#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace bytemorph::core::diagnostics {

enum class ErrorCode {
    None = 0,
    IoError,
    FileNotFound,
    EmptyInput,
    TruncatedData,
    InvalidMagic,
    UnsupportedFormat,
    UnsupportedArchitecture,
    ParseError,
    DisassemblyError,
    OutOfBounds,
    IntegerOverflow,
    InternalError,
    NotImplemented
};

[[nodiscard]] std::string_view error_code_name(ErrorCode code) noexcept;

struct Error {
    ErrorCode code{ErrorCode::None};
    std::string message;
    std::string context;

    [[nodiscard]] bool is_ok() const noexcept { return code == ErrorCode::None; }
    [[nodiscard]] std::string to_string() const;
};

template <typename T>
class Result {
public:
    Result(T value) : storage_(std::move(value)) {}
    Result(Error error) : storage_(std::move(error)) {}

    [[nodiscard]] static Result<T> ok(T value) { return Result<T>(std::move(value)); }
    [[nodiscard]] static Result<T> err(ErrorCode code, std::string message, std::string context = {}) {
        return Result<T>(Error{code, std::move(message), std::move(context)});
    }

    [[nodiscard]] bool has_value() const noexcept { return std::holds_alternative<T>(storage_); }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }

    [[nodiscard]] const T& value() const& { return std::get<T>(storage_); }
    [[nodiscard]] T& value() & { return std::get<T>(storage_); }
    [[nodiscard]] T&& value() && { return std::get<T>(std::move(storage_)); }

    [[nodiscard]] const Error& error() const& { return std::get<Error>(storage_); }

private:
    std::variant<T, Error> storage_;
};

template <>
class Result<void> {
public:
    Result() : error_(Error{ErrorCode::None, {}, {}}) {}
    Result(Error error) : error_(std::move(error)) {}

    [[nodiscard]] static Result<void> ok() { return Result<void>(); }
    [[nodiscard]] static Result<void> err(ErrorCode code, std::string message, std::string context = {}) {
        return Result<void>(Error{code, std::move(message), std::move(context)});
    }

    [[nodiscard]] bool has_value() const noexcept { return error_.is_ok(); }
    [[nodiscard]] explicit operator bool() const noexcept { return has_value(); }
    [[nodiscard]] const Error& error() const& { return error_; }

private:
    Error error_;
};

} // namespace bytemorph::core::diagnostics
