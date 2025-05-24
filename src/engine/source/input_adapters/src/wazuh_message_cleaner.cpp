#include "input_adapters/wazuh_message_cleaner.hpp"
#include <base/logging.hpp> 
#include <cstring>      // For strchr, strlen

// Wazuh C library includes - for constants or utility functions if absolutely necessary,
// but aim for C++ reimplementation of logic.
extern "C" {
    #include "shared/defs.h" // For OS_MAXSTR, queue type prefixes if used directly
}

namespace wazuh::engine::input_adapters
{

// Radically simplified helper function to map char prefix to MessageSourceType
MessageSourceType map_char_to_source_type_radically_simplified(char prefix_char) {
    switch (prefix_char) {
        case LOCALFILE_MQ: // Typically '1'
            return MessageSourceType::LOCALFILE_MQ_EVENT;
        case SYSLOG_MQ:    // Typically '2'
            return MessageSourceType::SYSLOG_EVENT; 
        // Other types (like AGENT_EVENT '4') will be mapped to UNKNOWN by this simplified function
        default:
            return MessageSourceType::UNKNOWN;
    }
}

CleanedMessageData WazuhMessageCleaner::cleanMessage(const char* raw_msg_from_queue)
{
    CleanedMessageData data; // Defaults: parsing_error=false, source_type=UNKNOWN, optionals=nullopt, strings=""

    // Initialize all fields that are not set by default constructor if necessary
    // These are already default-initialized by CleanedMessageData constructor as per wazuh_queue_reader.hpp
    // data.agent_id = ""; // Will be set to "000" or parsed
    // data.agent_name = "";
    // data.agent_ip = "";
    // data.location = "";
    // data.actual_log_payload = "";
    // data.extracted_timestamp = std::nullopt;
    // data.extracted_hostname = "";
    // data.extracted_program_name = "";
    data.parsing_error = true; // Default to error, clear on success

    if (!raw_msg_from_queue || *raw_msg_from_queue == '\0') {
        LOG_WARN("WazuhMessageCleaner: Received null or empty raw message.");
        if (raw_msg_from_queue) data.raw_full_message = raw_msg_from_queue; 
        else data.raw_full_message = "";
        return data; // parsing_error remains true
    }
    data.raw_full_message = raw_msg_from_queue;

    const char* content_ptr = raw_msg_from_queue;
    
    // 1. Extract the first character as the message type prefix.
    //    Set cleaned_data.source_type based on this. Advance raw_msg_from_queue pointer.
    if (strlen(raw_msg_from_queue) >= 2 && raw_msg_from_queue[1] == ':') {
        char type_prefix_char = raw_msg_from_queue[0];
        data.source_type = map_char_to_source_type_radically_simplified(type_prefix_char);
        content_ptr = raw_msg_from_queue + 2; // Skip "X:"
        if (data.source_type == MessageSourceType::UNKNOWN && type_prefix_char != '?') {
             LOG_DEBUG("WazuhMessageCleaner: Unhandled type prefix '{}' in simplified parser. Original raw: '{}'", type_prefix_char, raw_msg_from_queue);
        }
    } else {
        data.source_type = MessageSourceType::UNKNOWN; // No "X:" prefix or too short
        LOG_DEBUG("WazuhMessageCleaner: Message does not have standard 'X:' prefix. Raw: '{}'", raw_msg_from_queue);
        // content_ptr remains raw_msg_from_queue, parsing will proceed on the whole message
    }

    // 2. Find the first colon ':' in the remaining content.
    const char* first_colon = strchr(content_ptr, ':');

    if (first_colon) {
        // 3. Everything before the first colon is cleaned_data.location.
        if (first_colon - content_ptr > 0) { // Location is not empty
            data.location.assign(content_ptr, first_colon - content_ptr);
        } else {
            data.location = ""; // Empty location if colon is the first char
        }
        // 4. Everything after the first colon is cleaned_data.actual_log_payload.
        data.actual_log_payload = first_colon + 1;
        data.parsing_error = false; // Basic parsing successful
    } else {
        // No colon: the whole remaining string is payload, location is "unknown_location".
        data.actual_log_payload = content_ptr;
        data.location = "unknown_location"; // Default location
        // Set parsing_error = true if a colon was expected (i.e., if source_type was determined and not UNKNOWN)
        data.parsing_error = (data.source_type != MessageSourceType::UNKNOWN); 
        if(data.parsing_error) {
            LOG_WARN("WazuhMessageCleaner: No colon for location/payload split in typed message. Type: '{}', Raw: '{}'", static_cast<char>(data.source_type), raw_msg_from_queue);
        }
    }
    
    // 5. Set cleaned_data.agent_id to "000".
    data.agent_id = "000"; 
    
    // 6. Set all other fields to default/empty values (already done by CleanedMessageData constructor).
    data.agent_name = "";
    data.agent_ip = "";
    // extracted_timestamp, extracted_hostname, extracted_program_name already default

    // Trim whitespace from key fields that were populated
    auto trim_string_inplace = [](std::string& s) {
        if (s.empty()) return;
        s.erase(0, s.find_first_not_of(" \t\n\r\f\v"));
        s.erase(s.find_last_not_of(" \t\n\r\f\v") + 1);
    };
    trim_string_inplace(data.location);
    trim_string_inplace(data.actual_log_payload);
    // agent_id is fixed "000", no need to trim.

    // Final check: if payload ended up empty, it might be an issue.
    if (data.actual_log_payload.empty() && !data.parsing_error) {
        LOG_DEBUG("WazuhMessageCleaner: Resulting actual_log_payload is empty. Raw: '{}'", raw_msg_from_queue);
    }

    LOG_DEBUG("WazuhMessageCleaner (Radically Simplified): Cleaned: AgentID='{}', Loc='{}', Type='{}', Error:{} Payload='{}'",
        data.agent_id, data.location, static_cast<char>(data.source_type), data.parsing_error, data.actual_log_payload);

    return data;
}

} // namespace wazuh::engine::input_adapters
