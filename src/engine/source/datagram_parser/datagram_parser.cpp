#include "datagram_parser.hpp" // Self
#include "base/json.hpp"
#include "base/utils/timeUtils.hpp" // For base::utils::time::nowISO()
#include <string>
#include <optional>
#include <cctype>   // For isdigit
#include <algorithm> // For std::find if needed, though direct string operations are used here

namespace com::wazuh::engine::datagram_parser {

std::optional<json::Json> split_datagram_to_json(const std::string& raw_datagram) {
    // Validation: Must not be empty.
    if (raw_datagram.empty()) {
        return std::nullopt;
    }

    // Validation: First character must be a digit.
    if (!isdigit(raw_datagram[0])) {
        return std::nullopt;
    }

    // Validation: Must contain at least two colons.
    size_t first_colon = raw_datagram.find(':');
    if (first_colon == std::string::npos) {
        return std::nullopt;
    }

    size_t second_colon = raw_datagram.find(':', first_colon + 1);
    if (second_colon == std::string::npos) {
        return std::nullopt;
    }

    // Split the raw_datagram string
    std::string queue_id_str = raw_datagram.substr(0, first_colon);
    std::string location_str = raw_datagram.substr(first_colon + 1, second_colon - (first_colon + 1));
    std::string message_str = raw_datagram.substr(second_colon + 1);

    // Construct a json::Json object
    json::Json event_json;
    event_json.setObject(); // Ensure it's an object
    event_json.set("/legacy_datagram/queue", queue_id_str);
    event_json.set("/legacy_datagram/location", location_str);
    event_json.set("/legacy_datagram/message", message_str);
    event_json.set("/event/kind", "datagram");
    event_json.set("/event/type", "legacy_wazuh");
    event_json.set("/timestamp", base::utils::time::nowISO());

    return event_json;
}

} // namespace com::wazuh::engine::datagram_parser
