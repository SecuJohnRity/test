#ifndef DATAGRAM_PARSER_HPP
#define DATAGRAM_PARSER_HPP

#include <string>
#include <optional>
#include "base/json.hpp" // Include for json::Json

namespace com::wazuh::engine::datagram_parser {

// New function:
std::optional<json::Json> split_datagram_to_json(const std::string& raw_datagram);

} // namespace com::wazuh::engine::datagram_parser

#endif // DATAGRAM_PARSER_HPP
