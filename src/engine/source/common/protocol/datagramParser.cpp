#include "datagramParser.hpp"

#include <regex>
#include <iostream> // For std::cerr for logging errors, replace with proper logging if available
#include <base/logging.hpp> // Assuming this is the logging utility
#include <base/utils/timeUtils.hpp> // For timestamp parsing/conversion if available

namespace common::protocol
{

// Define a regex based on the assumed datagram format:
// location_indicator priority timestamp hostname program_name[pid]: message_content
// This regex is a starting point and might need refinement.
// Example: Oct 25 10:20:30 myhost sudo[12345]: USER_COMMAND=/usr/bin/id
// Example: (syscheck) 1698228030 myagent ossec-agent: INFO: Starting syscheck scan.
// Example: /var/log/auth.log Oct 25 10:20:31 server1 sshd[5432]: Accepted publickey for user
// This regex attempts to be general.
// Group 1: Optional location (e.g., "(syscheck) ", "/var/log/auth.log ")
// Group 2: Timestamp (e.g., "Oct 25 10:20:30", "1698228030")
// Group 3: Hostname (e.g., "myhost", "myagent", "server1")
// Group 4: Program name (e.g., "sudo", "ossec-agent", "sshd")
// Group 5: Optional PID (e.g., "12345", "5432")
// Group 6: Message content
const std::regex DATAGRAM_REGEX(
    R"(^(\S*\s+|[^ ]+\s+)?)" // Optional location/priority part
    R"((Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{10,})\s+)" // Timestamp (syslog or epoch)
    R"((\S+)\s+)"              // Hostname
    R"(([^\[:]+))"             // Program name
    R"(?:\[(\d+)\])?:\s+)"     // Optional PID, followed by ':' and space
    R"((.*)$)"                 // Message content
);

// More specific regex if the above is too general or has issues with captures.
// This one is more aligned with typical syslog messages.
const std::regex SYSLOG_STYLE_REGEX(
   R"(^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{10,})\s+)" // Group 1: Timestamp
   R"((\S+)\s+)"                                                                                      // Group 2: Hostname
   R"(([^\[:]+))"                                                                                     // Group 3: Program name
   R"(?:\[(\d+)\])?:\s+)"                                                                              // Group 4: Optional PID
   R"((.*)$)"                                                                                         // Group 5: Message
);


ProtocolHandler getDatagramParser()
{
    return [](std::string&& datagram_str) -> std::queue<base::Event>
    {
        std::queue<base::Event> events;
        std::smatch match;

        // Attempt to parse the datagram string
        // For now, using SYSLOG_STYLE_REGEX. The DATAGRAM_REGEX can be tried if this is not adequate.
        // The original `datagram_str` is captured by copy for potential use in the JSON event.
        std::string original_event_str = datagram_str;

        if (std::regex_match(datagram_str, match, SYSLOG_STYLE_REGEX))
        {
            if (match.size() == 6) // Expecting 5 captures + the whole match
            {
                auto event_json = std::make_shared<json::Json>();
                
                // Field 1: Timestamp
                std::string timestamp_str = match[1].str();
                // TODO: Convert timestamp_str to a normalized ISO 8601 format if possible.
                // For now, storing as is or using base::utils::TimeUtils if available.
                // Example: event_json->setString(base::utils::TimeUtils::parseAndFormat(timestamp_str), "/timestamp");
                event_json->setString(timestamp_str, "/timestamp"); // Placeholder

                // Field 2: Hostname
                event_json->setString(match[2].str(), "/hostname");

                // Field 3: Program Name
                event_json->setString(match[3].str(), "/program_name");

                // Field 4: PID (Optional)
                if (match[4].matched)
                {
                    event_json->setString(match[4].str(), "/pid");
                }

                // Field 5: Message
                event_json->setString(match[5].str(), "/message");
                
                // Store the original event string
                event_json->setString(original_event_str, "/original_event");

                // Add a "parser" field to indicate it came from this parser
                event_json->setString("datagram_parser", "/parser_type");

                events.push(event_json);
            }
            else
            {
                // This case should ideally not happen if regex_match is true and regex is correct.
                LOG_ERROR("Datagram parsed with SYSLOG_STYLE_REGEX but unexpected match count: {}. Datagram: '{}'", match.size(), original_event_str);
            }
        }
        else
        {
            // Fallback or attempt with the more general DATAGRAM_REGEX if SYSLOG_STYLE_REGEX fails
            // For now, just log an error if SYSLOG_STYLE_REGEX fails.
            // A more robust implementation might try multiple regexes or parsing strategies.
            LOG_WARNING("Failed to parse datagram using SYSLOG_STYLE_REGEX: '{}'", original_event_str);
            // Optionally, create a raw event if parsing fails but you still want to ingest it
            /*
            auto event_json = std::make_shared<json::Json>();
            event_json->setString(original_event_str, "/raw_message");
            event_json->setString("datagram_parser_failed", "/parser_type");
            events.push(event_json);
            */
        }

        return events;
    };
}

} // namespace common::protocol
