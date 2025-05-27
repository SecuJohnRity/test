#ifndef _COMMON_PROTOCOL_DATAGRAMPARSER_HPP
#define _COMMON_PROTOCOL_DATAGRAMPARSER_HPP

#include <functional>
#include <queue>
#include <string>

#include <base/baseTypes.hpp> // For base::Event and json::Json

namespace common::protocol
{

// Type alias for the protocol handler function, consistent with ndJsonParser
using ProtocolHandler = std::function<std::queue<base::Event>(std::string&&)>;

/**
 * @brief Gets a datagram parser function.
 *
 * The returned function takes a raw datagram string and returns a queue
 * of base::Event objects. Typically, for a single datagram, this queue
 * will contain one event, or be empty if parsing fails.
 *
 * @return A ProtocolHandler function for parsing datagrams.
 */
ProtocolHandler getDatagramParser();

} // namespace common::protocol

#endif // _COMMON_PROTOCOL_DATAGRAMPARSER_HPP
