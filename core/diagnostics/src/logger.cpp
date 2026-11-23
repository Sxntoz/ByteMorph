#include "bytemorph/core/diagnostics/logger.hpp"

#include <iostream>

namespace bytemorph::core::diagnostics {

std::string_view log_level_name(LogLevel level) noexcept {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warn: return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Off: return "OFF";
    }
    return "UNKNOWN";
}

Logger& Logger::instance() {
    static Logger inst;
    return inst;
}

Logger::Logger() {
    reset_default_sink();
}

void Logger::set_level(LogLevel level) noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    level_ = level;
}

LogLevel Logger::level() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return level_;
}

void Logger::set_sink(SinkFn sink) {
    std::lock_guard<std::mutex> lock(mutex_);
    sink_ = std::move(sink);
}

void Logger::reset_default_sink() {
    std::lock_guard<std::mutex> lock(mutex_);
    sink_ = [](LogLevel lvl, std::string_view component, std::string_view message) {
        std::cerr << "[" << log_level_name(lvl) << "] [" << component << "] " << message << '\n';
    };
}

void Logger::log(LogLevel level, std::string_view component, std::string_view message) {
    SinkFn sink_copy;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (level < level_ || level_ == LogLevel::Off || !sink_) {
            return;
        }
        sink_copy = sink_;
    }
    sink_copy(level, component, message);
}

} // namespace bytemorph::core::diagnostics
