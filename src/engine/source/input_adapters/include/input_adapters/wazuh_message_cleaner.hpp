#ifndef ENGINE_WAZUH_MESSAGE_CLEANER_HPP
#define ENGINE_WAZUH_MESSAGE_CLEANER_HPP

#include "input_adapters/wazuh_queue_reader.hpp" // For CleanedMessageData and MessageSourceType
#include <string>

namespace wazuh::engine::input_adapters
{

class WazuhMessageCleaner
{
public:
    /**
     * @brief Cleans and parses a raw message from a Wazuh queue.
     * 
     * This function aims to replicate the initial processing done by analysisd's OS_CleanMSG,
     * extracting metadata like agent ID, location, and attempting to parse common log formats
     * to identify a timestamp and the actual log payload.
     * 
     * @param raw_msg_from_queue The null-terminated string message as read from the queue.
     * @return CleanedMessageData A struct containing the parsed components of the message.
     */
    static CleanedMessageData cleanMessage(const char* raw_msg_from_queue);

private:
    // Private helper methods can be added here if needed for complex parsing logic.
    // For example:
    // static std::optional<long> parse_syslog_timestamp(const std::string& log_part, std::string& remaining_log);
    // static void extract_agent_info_from_location(const std::string& location, CleanedMessageData& data);
};

} // namespace wazuh::engine::input_adapters

#endif // ENGINE_WAZUH_MESSAGE_CLEANER_HPP
