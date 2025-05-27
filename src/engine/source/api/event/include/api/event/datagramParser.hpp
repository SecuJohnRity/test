#ifndef _API_EVENT_DATAGRAMPARSER_HPP
#define _API_EVENT_DATAGRAMPARSER_HPP

#include <functional>
#include <queue>
#include <stdexcept>
#include <string>

#include <fmt/format.h> // For error messages
#include "base/baseTypes.hpp" // For base::Event and json::Json
// The path to datagram_parser.hpp needs to be relative to the include paths configured in CMake
// Assuming datagram_parser module's include path will be correctly set up.
#include "datagram_parser/datagram_parser.hpp" 

namespace api::event::protocol {

// Define ProtocolHandler, similar to how it's in ndJsonParser.hpp
// Ideally, this would be in a common header.
using ProtocolHandler = std::function<std::queue<base::Event>(std::string&&)>;

inline ProtocolHandler getDatagramParser() {
    return [](std::string&& batch) -> std::queue<base::Event> {
        if (batch.empty()) {
            // According to handlers.cpp, this should throw std::runtime_error
            throw std::runtime_error("Datagram parser error: empty batch/datagram string");
        }

        // Datagrams are single events, not batches of lines like NDJSON.
        // The 'batch' here is expected to be a single datagram string.
        
        std::optional<json::Json> parsed_json = com::wazuh::engine::datagram_parser::split_datagram_to_json(batch);

        if (!parsed_json) {
            // Throw std::runtime_error as expected by callers like pushEvent in handlers.cpp
            throw std::runtime_error(fmt::format("Datagram parser error: Failed to parse datagram: '{}'", batch));
        }

        std::queue<base::Event> events;
        // base::Event is std::shared_ptr<json::Json>
        events.push(std::make_shared<json::Json>(std::move(*parsed_json)));
        return events;
    };
}

} // namespace api::event::protocol

#endif // _API_EVENT_DATAGRAMPARSER_HPP
