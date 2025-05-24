#include "rootcheck_handler/wazuh_db_rootcheck_interface.hpp"
#include <base/logging.hpp>
#include <base/json.hpp> // For parsing/formatting if commands use JSON

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h> // For close, sleep
#include <cerrno>
#include <cstring> // For strerror, strncpy

// Wazuh C library includes for socket operations and paths
extern "C" {
    #include "shared/defs.h"      // For WDB_LOCAL_SOCK, OS_MAXSTR
    #include "os_net/os_net.h"    // For OS_ConnectUnixDomain, OS_SendSecureTCP, OS_RecvSecureTCP, OS_CloseSocket
    // wazuhdb_op.h might not be directly included; commands are typically strings.
}

// Fallback if WDB_LOCAL_SOCK is not in defs.h (it should be)
#ifndef WDB_LOCAL_SOCK
#define WDB_LOCAL_SOCK "queue/db/wdb"
#endif

namespace wazuh::engine::rootcheck_handler
{

// Constructor and Destructor
WazuhDbRootcheckInterface::WazuhDbRootcheckInterface(std::string wazuh_db_socket_path)
    : m_socket_path(std::move(wazuh_db_socket_path)), m_socket_fd(-1)
{
    if (m_socket_path.empty()) {
        char wazuh_path[OS_MAXSTR];
        if (getenv("WAZUH_HOME") != NULL) {
            snprintf(wazuh_path, sizeof(wazuh_path), "%s/%s", getenv("WAZUH_HOME") , WDB_LOCAL_SOCK);
            m_socket_path = wazuh_path;
        } else {
            // Fallback if WAZUH_HOME is not set, this might not be correct for all installations
            m_socket_path = "/" + std::string(WDB_LOCAL_SOCK); // e.g. /var/ossec/queue/db/wdb
        }
    }
    LOG_INFO("WazuhDbRootcheckInterface: Initialized for wazuh-db socket path '{}'.", m_socket_path);
}

WazuhDbRootcheckInterface::~WazuhDbRootcheckInterface()
{
    disconnect();
}

// Connection Management
bool WazuhDbRootcheckInterface::connect()
{
    if (m_socket_fd >= 0) {
        LOG_WARN("WazuhDbRootcheckInterface: Already connected.");
        return true;
    }
    // OS_ConnectUnixDomain is from os_net.h (Wazuh C library)
    m_socket_fd = OS_ConnectUnixDomain(m_socket_path.c_str(), SOCK_STREAM, OS_MAXSTR);
    if (m_socket_fd < 0) {
        LOG_ERROR("WazuhDbRootcheckInterface: Failed to connect to wazuh-db socket '{}': {}.", m_socket_path, strerror(errno));
        return false;
    }
    LOG_INFO("WazuhDbRootcheckInterface: Successfully connected to wazuh-db socket '{}' (fd: {}).", m_socket_path, m_socket_fd);
    return true;
}

void WazuhDbRootcheckInterface::disconnect()
{
    if (m_socket_fd >= 0) {
        OS_CloseSocket(m_socket_fd); // From os_net.h
        m_socket_fd = -1;
        LOG_INFO("WazuhDbRootcheckInterface: Disconnected from wazuh-db socket '{}'.", m_socket_path);
    }
}

// Command Sending and Receiving
bool WazuhDbRootcheckInterface::sendCommand(const std::string& command)
{
    if (m_socket_fd < 0) {
        LOG_ERROR("WazuhDbRootcheckInterface: Not connected. Cannot send command: {}", command);
        return false;
    }
    LOG_DEBUG("WazuhDbRootcheckInterface: Sending command: {}", command);
    // OS_SendSecureTCP is from os_net.h (Wazuh C library)
    if (OS_SendSecureTCP(m_socket_fd, command.length(), command.c_str()) != 0) {
        LOG_ERROR("WazuhDbRootcheckInterface: Failed to send command '{}' to wazuh-db: {}.", command, strerror(errno));
        disconnect(); // Consider connection broken
        return false;
    }
    return true;
}

std::optional<std::string> WazuhDbRootcheckInterface::receiveResponse()
{
    if (m_socket_fd < 0) {
        LOG_ERROR("WazuhDbRootcheckInterface: Not connected. Cannot receive response.");
        return std::nullopt;
    }
    char buffer[OS_MAXSTR + 1]; // OS_MAXSTR from defs.h
    // OS_RecvSecureTCP is from os_net.h (Wazuh C library)
    int received_len = OS_RecvSecureTCP(m_socket_fd, buffer, OS_MAXSTR);
    if (received_len > 0) {
        buffer[received_len] = '\0';
        LOG_DEBUG("WazuhDbRootcheckInterface: Received response: {}", buffer);
        return std::string(buffer);
    } else if (received_len == 0) {
        LOG_WARN("WazuhDbRootcheckInterface: wazuh-db socket closed connection (EOF).");
        disconnect(); // Connection closed
        return std::nullopt;
    } else { // received_len < 0
        LOG_ERROR("WazuhDbRootcheckInterface: Failed to receive response from wazuh-db: {}.", strerror(errno));
        disconnect(); // Assume connection error
        return std::nullopt;
    }
}

// --- Public Method Implementations ---

bool WazuhDbRootcheckInterface::storeRootcheckEntry(const std::string& agentId, const std::string& rootcheckData)
{
    // Command format: "agent [agent_id] rootcheck add [rootcheckData_json_or_formatted_string]"
    // The exact format of rootcheckData needs to be compatible with wazuh-db's 'rootcheck add' command.
    // If rootcheckData is a JSON string, it needs to be handled correctly by wazuh-db's parser (e.g., quotes escaped).
    // For PoC, assuming rootcheckData is a pre-formatted string or JSON that wazuh-db can take as the last argument.
    std::string command = "agent " + agentId + " rootcheck add " + rootcheckData;
    LOG_DEBUG("WazuhDbRootcheckInterface: storeRootcheckEntry command: {}", command);

    if (!sendCommand(command)) return false;
    
    auto response = receiveResponse();
    if (response && *response == "ok") {
        return true;
    }
    LOG_WARN("WazuhDbRootcheckInterface: Failed to store rootcheck entry. Response: {}", response.value_or("N/A"));
    return false;
}

bool WazuhDbRootcheckInterface::clearAgentRootcheck(const std::string& agentId)
{
    // Command format: "agent [agent_id] rootcheck clear"
    std::string command = "agent " + agentId + " rootcheck clear";
    LOG_DEBUG("WazuhDbRootcheckInterface: clearAgentRootcheck command: {}", command);

    if (!sendCommand(command)) return false;

    auto response = receiveResponse();
    if (response && *response == "ok") {
        return true;
    }
    LOG_WARN("WazuhDbRootcheckInterface: Failed to clear rootcheck data for agent {}. Response: {}", agentId, response.value_or("N/A"));
    return false;
}

bool WazuhDbRootcheckInterface::updateLastScan(const std::string& agentId, int64_t timestamp)
{
    // Command format: "agent [agent_id] rootcheck last_scan [timestamp_epoch_string]"
    std::string command = "agent " + agentId + " rootcheck last_scan " + std::to_string(timestamp);
    LOG_DEBUG("WazuhDbRootcheckInterface: updateLastScan command: {}", command);
    
    if (!sendCommand(command)) return false;

    auto response = receiveResponse();
    if (response && *response == "ok") {
        return true;
    }
    LOG_WARN("WazuhDbRootcheckInterface: Failed to update rootcheck last_scan for agent {}. Response: {}", agentId, response.value_or("N/A"));
    return false;
}

} // namespace wazuh::engine::rootcheck_handler
