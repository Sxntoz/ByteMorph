#pragma once

#include <functional>
#include <mutex>
#include <string>
#include <string_view>

namespace bytemorph::core::diagnostics {

enum class LogLevel {
    Trace = 0,
    Debug,
    Info,
    Warn,
    Error,
    Off
};

[[nodiscard]] std::string_view log_level_name(LogLevel level) noexcept;

class Logger {
public:
    using SinkFn = std::function<void(LogLevel, std::string_view, std::string_view)>;

    static Logger& instance();

    void set_level(LogLevel level) noexcept;
    [[nodiscard]] LogLevel level() const noexcept;

    void set_sink(SinkFn sink);
    void reset_default_sink();

    void log(LogLevel level, std::string_view component, std::string_view message);

    void trace(std::string_view component, std::string_view message) { log(LogLevel::Trace, component, message); }
    void debug(std::string_view component, std::string_view message) { log(LogLevel::Debug, component, message); }
    void info(std::string_view component, std::string_view message) { log(LogLevel::Info, component, message); }
    void warn(std::string_view component, std::string_view message) { log(LogLevel::Warn, component, message); }
    void error(std::string_view component, std::string_view message) { log(LogLevel::Error, component, message); }

private:
    Logger();

    mutable std::mutex mutex_;
    LogLevel level_{LogLevel::Warn};
    SinkFn sink_;
};

} // namespace bytemorph::core::diagnostics
