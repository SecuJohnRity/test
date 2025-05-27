#include "gtest/gtest.h"
#include "datagram_parser/datagram_parser.hpp" // Header for the function to test
#include "base/json.hpp"                     // For json::Json
#include "base/utils/timeUtils.hpp"          // For base::utils::time::nowISO() if needed for comparison (though we only check existence)

namespace com::wazuh::engine::datagram_parser {

// Test fixture for common setup, if any (not strictly needed for these tests)
class DatagramParserTest : public ::testing::Test {
protected:
    // You can define per-test-suite set-up and tear-down logic here.
    // void SetUp() override {}
    // void TearDown() override {}
};

TEST_F(DatagramParserTest, ValidTypicalDatagram) {
    const std::string datagram = "1:/var/log/syslog:Nov  9 16:06:26 localhost salute: Hello world.";
    auto result = split_datagram_to_json(datagram);

    ASSERT_TRUE(result.has_value());
    const auto& j = result.value();

    EXPECT_EQ(j.getString("/legacy_datagram/queue").value_or("ERROR"), "1");
    EXPECT_EQ(j.getString("/legacy_datagram/location").value_or("ERROR"), "/var/log/syslog");
    EXPECT_EQ(j.getString("/legacy_datagram/message").value_or("ERROR"), "Nov  9 16:06:26 localhost salute: Hello world.");
    EXPECT_EQ(j.getString("/event/kind").value_or("ERROR"), "datagram");
    EXPECT_EQ(j.getString("/event/type").value_or("ERROR"), "legacy_wazuh");
    EXPECT_TRUE(j.isString("/timestamp"));
    // Check timestamp is not empty
    EXPECT_FALSE(j.getString("/timestamp").value_or("").empty());
}

TEST_F(DatagramParserTest, ValidDatagramWithMessageColons) {
    const std::string datagram = "2:/some/path:User: admin logged in.";
    auto result = split_datagram_to_json(datagram);

    ASSERT_TRUE(result.has_value());
    const auto& j = result.value();

    EXPECT_EQ(j.getString("/legacy_datagram/queue").value_or("ERROR"), "2");
    EXPECT_EQ(j.getString("/legacy_datagram/location").value_or("ERROR"), "/some/path");
    EXPECT_EQ(j.getString("/legacy_datagram/message").value_or("ERROR"), "User: admin logged in.");
    EXPECT_EQ(j.getString("/event/kind").value_or("ERROR"), "datagram");
    EXPECT_EQ(j.getString("/event/type").value_or("ERROR"), "legacy_wazuh");
    EXPECT_TRUE(j.isString("/timestamp"));
}

TEST_F(DatagramParserTest, ValidMinimalDatagram) {
    const std::string datagram = "8::"; // Empty location, empty message
    auto result = split_datagram_to_json(datagram);

    ASSERT_TRUE(result.has_value());
    const auto& j = result.value();

    EXPECT_EQ(j.getString("/legacy_datagram/queue").value_or("ERROR"), "8");
    EXPECT_EQ(j.getString("/legacy_datagram/location").value_or("ERROR"), "");
    EXPECT_EQ(j.getString("/legacy_datagram/message").value_or("ERROR"), "");
    EXPECT_EQ(j.getString("/event/kind").value_or("ERROR"), "datagram");
    EXPECT_EQ(j.getString("/event/type").value_or("ERROR"), "legacy_wazuh");
    EXPECT_TRUE(j.isString("/timestamp"));
}

TEST_F(DatagramParserTest, InvalidEmptyDatagram) {
    const std::string datagram = "";
    auto result = split_datagram_to_json(datagram);
    EXPECT_FALSE(result.has_value());
}

TEST_F(DatagramParserTest, InvalidNoColons) {
    const std::string datagram = "1/var/log/syslogNoColon";
    auto result = split_datagram_to_json(datagram);
    EXPECT_FALSE(result.has_value());
}

TEST_F(DatagramParserTest, InvalidOneColon) {
    const std::string datagram = "1:/var/log/syslogOneColon";
    auto result = split_datagram_to_json(datagram);
    EXPECT_FALSE(result.has_value());
}

TEST_F(DatagramParserTest, InvalidNonDigitQueueID) {
    const std::string datagram = "a:/var/log/syslog:message";
    auto result = split_datagram_to_json(datagram);
    EXPECT_FALSE(result.has_value());
}

TEST_F(DatagramParserTest, InvalidQueueIDTooLongButFirstCharIsDigit) {
    // Current implementation only checks if the first char is a digit for queue_id.
    // This test reflects that; if validation becomes stricter, this test might need adjustment.
    const std::string datagram = "12:/var/log/syslog:message"; 
    auto result = split_datagram_to_json(datagram);
    
    // Based on current logic (first char '1' is digit, two colons exist), this should be "valid"
    // in terms of parsing structure, though "12" might be an unexpected queue_id semantically.
    // The split_datagram_to_json function doesn't validate the length or full numeric nature of queue_id beyond the first char.
    ASSERT_TRUE(result.has_value()); 
    const auto& j = result.value();
    EXPECT_EQ(j.getString("/legacy_datagram/queue").value_or("ERROR"), "12");
    EXPECT_EQ(j.getString("/legacy_datagram/location").value_or("ERROR"), "/var/log/syslog");
    EXPECT_EQ(j.getString("/legacy_datagram/message").value_or("ERROR"), "message");
}

TEST_F(DatagramParserTest, ValidDatagramEndsWithColon) {
    const std::string datagram = "3:/log/path:message ends with colon:";
    auto result = split_datagram_to_json(datagram);

    ASSERT_TRUE(result.has_value());
    const auto& j = result.value();
    EXPECT_EQ(j.getString("/legacy_datagram/queue").value_or("ERROR"), "3");
    EXPECT_EQ(j.getString("/legacy_datagram/location").value_or("ERROR"), "/log/path");
    EXPECT_EQ(j.getString("/legacy_datagram/message").value_or("ERROR"), "message ends with colon:");
}

TEST_F(DatagramParserTest, ValidDatagramLocationEmptyButMessagePresent) {
    const std::string datagram = "4::message only";
    auto result = split_datagram_to_json(datagram);

    ASSERT_TRUE(result.has_value());
    const auto& j = result.value();
    EXPECT_EQ(j.getString("/legacy_datagram/queue").value_or("ERROR"), "4");
    EXPECT_EQ(j.getString("/legacy_datagram/location").value_or("ERROR"), "");
    EXPECT_EQ(j.getString("/legacy_datagram/message").value_or("ERROR"), "message only");
}

TEST_F(DatagramParserTest, ValidDatagramMessageEmptyButLocationPresent) {
    const std::string datagram = "5:/location/only:";
    auto result = split_datagram_to_json(datagram);

    ASSERT_TRUE(result.has_value());
    const auto& j = result.value();
    EXPECT_EQ(j.getString("/legacy_datagram/queue").value_or("ERROR"), "5");
    EXPECT_EQ(j.getString("/legacy_datagram/location").value_or("ERROR"), "/location/only");
    EXPECT_EQ(j.getString("/legacy_datagram/message").value_or("ERROR"), "");
}

} // namespace com::wazuh::engine::datagram_parser
