#include <gtest/gtest.h>
#include "common/protocol/datagramParser.hpp" // SUT
#include "base/json.hpp" // For inspecting base::Event (json::Json)
#include <queue>

// Mock or minimal logging if needed by parser, or ensure logging doesn't break tests
// For example, if base/logging.hpp is used by the parser:
#include <base/logging.hpp>
// Might need a minimal logging setup for tests if not already handled globally:
class DatagramParserTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() {
        // Initialize logging if it's required by the parser and not auto-initialized
        // Example: if logging::start is available and needed:
        // logging::LoggingConfig logConfig;
        // logConfig.level = logging::Level::Debug; // Or Error to suppress logs
        // logging::start(logConfig);
        // For now, assuming logging is handled or not strictly required for parser logic to be tested.
        // If tests fail due to logging, this is where to initialize it.
    }

    static void TearDownTestSuite() {
        // logging::stop(); // If started in SetUpTestSuite
    }
};


TEST_F(DatagramParserTest, ParseValidSyslogLikeEvent) {
    auto parser = common::protocol::getDatagramParser();
    std::string datagram = "Oct 25 10:20:30 myhost sudo[12345]: Test message content";
    std::queue<base::Event> events = parser(std::move(datagram));

    ASSERT_EQ(events.size(), 1);
    ASSERT_TRUE(events.front() != nullptr);

    const auto& event_json = *events.front();
    EXPECT_EQ(event_json.getString("/timestamp").value_or(""), "Oct 25 10:20:30");
    EXPECT_EQ(event_json.getString("/hostname").value_or(""), "myhost");
    EXPECT_EQ(event_json.getString("/program_name").value_or(""), "sudo");
    EXPECT_EQ(event_json.getString("/pid").value_or(""), "12345");
    EXPECT_EQ(event_json.getString("/message").value_or(""), "Test message content");
    EXPECT_EQ(event_json.getString("/original_event").value_or(""), "Oct 25 10:20:30 myhost sudo[12345]: Test message content");
    EXPECT_EQ(event_json.getString("/parser_type").value_or(""), "datagram_parser");
}

TEST_F(DatagramParserTest, ParseValidEventNoPid) {
    auto parser = common::protocol::getDatagramParser();
    std::string datagram = "Nov 10 12:00:00 anotherhost appname: Event without PID";
    std::queue<base::Event> events = parser(std::move(datagram));

    ASSERT_EQ(events.size(), 1);
    ASSERT_TRUE(events.front() != nullptr);

    const auto& event_json = *events.front();
    EXPECT_EQ(event_json.getString("/timestamp").value_or(""), "Nov 10 12:00:00");
    EXPECT_EQ(event_json.getString("/hostname").value_or(""), "anotherhost");
    EXPECT_EQ(event_json.getString("/program_name").value_or(""), "appname");
    EXPECT_FALSE(event_json.exists("/pid")); // PID should not be present
    EXPECT_EQ(event_json.getString("/message").value_or(""), "Event without PID");
}

TEST_F(DatagramParserTest, ParseEpochTimestampEvent) {
    auto parser = common::protocol::getDatagramParser();
    // The SYSLOG_STYLE_REGEX in datagramParser.cpp is:
    // R"(^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{10,})\s+)"
    // This part `|\d{10,}` should match epoch timestamps.
    std::string datagram = "1698228030 myagent ossec-agent: INFO: Starting syscheck scan.";
    std::queue<base::Event> events = parser(std::move(datagram));
    
    ASSERT_EQ(events.size(), 1);
    ASSERT_TRUE(events.front() != nullptr);
    const auto& event_json = *events.front();
    EXPECT_EQ(event_json.getString("/timestamp").value_or(""), "1698228030");
    EXPECT_EQ(event_json.getString("/hostname").value_or(""), "myagent");
    EXPECT_EQ(event_json.getString("/program_name").value_or(""), "ossec-agent");
    EXPECT_FALSE(event_json.exists("/pid"));
    EXPECT_EQ(event_json.getString("/message").value_or(""), "INFO: Starting syscheck scan.");
}

TEST_F(DatagramParserTest, ParseMalformedDatagram) {
    auto parser = common::protocol::getDatagramParser();
    std::string datagram = "This is not a valid datagram";
    std::queue<base::Event> events = parser(std::move(datagram));

    // Expecting it to fail parsing and return an empty queue
    EXPECT_TRUE(events.empty());
    // The parser logs a warning on failure, which is good. Test doesn't check logs here.
}

TEST_F(DatagramParserTest, ParseDatagramWithExtraSpaces) {
    auto parser = common::protocol::getDatagramParser();
    // Note: The current regex `:\s+` expects at least one space after colon.
    // If it was `:\s*`, it could handle zero spaces.
    std::string datagram = "Dec  1 01:02:03  spacedhost  program[99]:  Lots  of   spaces";
    std::queue<base::Event> events = parser(std::move(datagram));

    ASSERT_EQ(events.size(), 1);
    const auto& event_json = *events.front();
    EXPECT_EQ(event_json.getString("/timestamp").value_or(""), "Dec  1 01:02:03");
    EXPECT_EQ(event_json.getString("/hostname").value_or(""), "spacedhost"); // Hostname regex `(\S+)` handles this
    EXPECT_EQ(event_json.getString("/program_name").value_or(""), "program");
    EXPECT_EQ(event_json.getString("/pid").value_or(""), "99");
    EXPECT_EQ(event_json.getString("/message").value_or(""), " Lots  of   spaces"); // Message `(.*)$` captures the rest
}

TEST_F(DatagramParserTest, ParseEmptyDatagram) {
    auto parser = common::protocol::getDatagramParser();
    std::string datagram = "";
    std::queue<base::Event> events = parser(std::move(datagram));
    EXPECT_TRUE(events.empty()); // Empty string should not match and result in no events
}

TEST_F(DatagramParserTest, ParseOnlyTimestampAndHost) {
    auto parser = common::protocol::getDatagramParser();
    std::string datagram = "Oct 25 10:20:30 myhost"; // Missing program_name and message
    std::queue<base::Event> events = parser(std::move(datagram));
    EXPECT_TRUE(events.empty()); // Should fail to parse as it doesn't match the full regex structure
}

TEST_F(DatagramParserTest, ParseMissingColonAfterPid) {
    auto parser = common::protocol::getDatagramParser();
    std::string datagram = "Oct 25 10:20:30 myhost sudo[12345] Test message content"; // Missing ':'
    std::queue<base::Event> events = parser(std::move(datagram));
    EXPECT_TRUE(events.empty()); // Should fail due to missing ':'
}

TEST_F(DatagramParserTest, ParseNoSpaceAfterColon) {
    auto parser = common::protocol::getDatagramParser();
    // The regex `(?:\[(\d+)\])?:\s+` requires at least one space after the colon.
    std::string datagram = "Oct 25 10:20:30 myhost sudo[12345]:Test message content"; 
    std::queue<base::Event> events = parser(std::move(datagram));
    // This test's success depends on whether `\s+` (one or more spaces) or `\s*` (zero or more) is desired.
    // Given the current regex with `\s+`, this should fail.
    EXPECT_TRUE(events.empty()); 
}

TEST_F(DatagramParserTest, ParseProgramNameWithHyphen) {
    auto parser = common::protocol::getDatagramParser();
    std::string datagram = "Jan  1 00:00:00 test-host my-program-name[123]: Message";
    std::queue<base::Event> events = parser(std::move(datagram));
    ASSERT_EQ(events.size(), 1);
    const auto& event_json = *events.front();
    EXPECT_EQ(event_json.getString("/program_name").value_or(""), "my-program-name");
    EXPECT_EQ(event_json.getString("/message").value_or(""), "Message");
}

TEST_F(DatagramParserTest, ParseProgramNameWithNumbers) {
    auto parser = common::protocol::getDatagramParser();
    std::string datagram = "Jan  1 00:00:00 test-host app123[123]: Message";
    std::queue<base::Event> events = parser(std::move(datagram));
    ASSERT_EQ(events.size(), 1);
    const auto& event_json = *events.front();
    EXPECT_EQ(event_json.getString("/program_name").value_or(""), "app123");
    EXPECT_EQ(event_json.getString("/message").value_or(""), "Message");
}

// This test might fail if the DATAGRAM_REGEX is not used or if SYSLOG_STYLE_REGEX is too strict
// For example, the SYSLOG_STYLE_REGEX currently does not have a capture group for location.
// If the intention is to support location prefixes like "(syscheck) " or "/var/log/auth.log ",
// the SYSLOG_STYLE_REGEX in datagramParser.cpp would need to be adjusted, or the more general
// DATAGRAM_REGEX (commented out in the .cpp file) would need to be used and refined.
// For now, this test assumes that such prefixes are NOT standard for SYSLOG_STYLE_REGEX
// and thus the parser (using SYSLOG_STYLE_REGEX) would fail.
TEST_F(DatagramParserTest, ParseWithLocationIndicatorSyslogStyle) {
    auto parser = common::protocol::getDatagramParser();
    std::string datagram = "(syscheck) Oct 25 10:20:30 myhost sudo[12345]: Test message";
    std::queue<base::Event> events = parser(std::move(datagram));
    // Current SYSLOG_STYLE_REGEX does not account for a leading arbitrary string before timestamp.
    EXPECT_TRUE(events.empty()); 
}
