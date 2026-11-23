#include "bytemorph/core/diagnostics/error.hpp"
#include "bytemorph/core/diagnostics/logger.hpp"

#include <gtest/gtest.h>

using namespace bytemorph::core::diagnostics;

TEST(DiagnosticsTest, ResultSuccessAndError) {
    auto ok = Result<int>::ok(42);
    ASSERT_TRUE(ok.has_value());
    EXPECT_EQ(ok.value(), 42);

    auto fail = Result<int>::err(ErrorCode::TruncatedData, "short buffer", "UnitTest");
    ASSERT_FALSE(fail.has_value());
    EXPECT_EQ(fail.error().code, ErrorCode::TruncatedData);
    EXPECT_NE(fail.error().to_string().find("TruncatedData"), std::string::npos);
    EXPECT_NE(fail.error().to_string().find("UnitTest"), std::string::npos);
}

TEST(DiagnosticsTest, LoggerFiltersByLevel) {
    auto& logger = Logger::instance();
    std::vector<std::string> captured;
    logger.set_sink([&](LogLevel, std::string_view comp, std::string_view msg) {
        captured.emplace_back(std::string(comp) + ":" + std::string(msg));
    });
    logger.set_level(LogLevel::Warn);
    logger.info("Test", "ignored");
    logger.warn("Test", "kept");
    logger.reset_default_sink();

    ASSERT_EQ(captured.size(), 1u);
    EXPECT_EQ(captured[0], "Test:kept");
}
