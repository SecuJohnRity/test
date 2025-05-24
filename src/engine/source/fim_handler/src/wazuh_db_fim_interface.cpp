#include "fim_handler/wazuh_db_fim_interface.hpp"
#include <base/logging.hpp>
#include <base/json.hpp> // For potential use in formatting or parsing complex responses if needed

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h> // For close, sleep
#include <cerrno>
#include <cstring> // For strerror, strncpy

// Wazuh C library includes for socket operations and paths
extern "C" {
    #include "shared/defs.h"      // For WDB_LOCAL_SOCK, OS_MAXSTR
    #include "os_net/os_net.h"    // For OS_ConnectUnixDomain, OS_SendSecureTCP, OS_RecvSecureTCP, OS_CloseSocket
    // wazuhdb_op.h is not typically included directly for socket commands,
    // but defs.h provides WDB_LOCAL_SOCK.
}

// Fallback if WDB_LOCAL_SOCK is not in defs.h (it should be)
#ifndef WDB_LOCAL_SOCK
#define WDB_LOCAL_SOCK "queue/db/wdb"
#endif

namespace wazuh::engine::fim_handler
{

// Helper to convert FIMScanType to string for wazuh-db command
std::string WazuhDbFimInterface::scanTypeToString(FIMScanType scanType) const {
    switch (scanType) {
        case FIMScanType::START_SCAN: return "start";
        case FIMScanType::END_SCAN: return "end";
        case FIMScanType::END_FIRST_SCAN: return "end_first";
        default: return "unknown";
    }
}

WazuhDbFimInterface::WazuhDbFimInterface(std::string wazuh_db_socket_path)
    : m_socket_path(std::move(wazuh_db_socket_path)), m_socket_fd(-1)
{
    if (m_socket_path.empty()) {
        // Construct the default path if needed.
        // Assuming Wazuh installation prefix might be needed or it's relative to a known root.
        // For now, using WDB_LOCAL_SOCK directly if it's a relative path from root.
        // If WAZUH_HOME is set, it could be: std::string(getenv("WAZUH_HOME") ? getenv("WAZUH_HOME") : "") + "/" + WDB_LOCAL_SOCK;
        // For simplicity, let's assume WDB_LOCAL_SOCK is the correct relative path from a base dir,
        // or it's an absolute path if configured that way in defs.h
        // This might need adjustment based on how Wazuh environment variables are handled in the engine.
        char wazuh_path[OS_MAXSTR];
        if (getenv("WAZUH_HOME") != NULL) {
            snprintf(wazuh_path, sizeof(wazuh_path), "%s/%s", getenv("WAZUH_HOME") , WDB_LOCAL_SOCK);
            m_socket_path = wazuh_path;
        } else {
             // Fallback if WAZUH_HOME is not set, this might not be correct for all installations
            m_socket_path = "/" + std::string(WDB_LOCAL_SOCK); // e.g. /var/ossec/queue/db/wdb
        }
    }
    LOG_INFO("WazuhDbFimInterface: Initialized for wazuh-db socket path '{}'.", m_socket_path);
}

WazuhDbFimInterface::~WazuhDbFimInterface()
{
    disconnect();
}

bool WazuhDbFimInterface::connect()
{
    if (m_socket_fd >= 0) {
        LOG_WARN("WazuhDbFimInterface: Already connected.");
        return true;
    }
    // OS_ConnectUnixDomain is from os_net.h (Wazuh C library)
    // It expects path, type (SOCK_STREAM for wazuh-db), max_msg_size
    m_socket_fd = OS_ConnectUnixDomain(m_socket_path.c_str(), SOCK_STREAM, OS_MAXSTR);
    if (m_socket_fd < 0) {
        LOG_ERROR("WazuhDbFimInterface: Failed to connect to wazuh-db socket '{}': {}.", m_socket_path, strerror(errno));
        return false;
    }
    LOG_INFO("WazuhDbFimInterface: Successfully connected to wazuh-db socket '{}' (fd: {}).", m_socket_path, m_socket_fd);
    return true;
}

void WazuhDbFimInterface::disconnect()
{
    if (m_socket_fd >= 0) {
        OS_CloseSocket(m_socket_fd); // From os_net.h
        m_socket_fd = -1;
        LOG_INFO("WazuhDbFimInterface: Disconnected from wazuh-db socket '{}'.", m_socket_path);
    }
}

bool WazuhDbFimInterface::sendCommand(const std::string& command)
{
    if (m_socket_fd < 0) {
        LOG_ERROR("WazuhDbFimInterface: Not connected. Cannot send command: {}", command);
        return false;
    }
    // OS_SendSecureTCP is from os_net.h (Wazuh C library)
    // int OS_SendSecureTCP(int sock, uint32_t size, const void * msg)
    LOG_DEBUG("WazuhDbFimInterface: Sending command: {}", command);
    if (OS_SendSecureTCP(m_socket_fd, command.length(), command.c_str()) != 0) {
        LOG_ERROR("WazuhDbFimInterface: Failed to send command '{}' to wazuh-db: {}.", command, strerror(errno));
        // Consider connection broken, so disconnect to force reconnect on next op
        disconnect(); 
        return false;
    }
    return true;
}

std::optional<std::string> WazuhDbFimInterface::receiveResponse()
{
    if (m_socket_fd < 0) {
        LOG_ERROR("WazuhDbFimInterface: Not connected. Cannot receive response.");
        return std::nullopt;
    }
    char buffer[OS_MAXSTR + 1]; // OS_MAXSTR from defs.h
    // OS_RecvSecureTCP is from os_net.h (Wazuh C library)
    // int OS_RecvSecureTCP(int sock, char * ret, uint32_t size)
    int received_len = OS_RecvSecureTCP(m_socket_fd, buffer, OS_MAXSTR);
    if (received_len > 0) {
        buffer[received_len] = '\0';
        LOG_DEBUG("WazuhDbFimInterface: Received response: {}", buffer);
        return std::string(buffer);
    } else if (received_len == 0) {
        LOG_WARN("WazuhDbFimInterface: wazuh-db socket closed connection (EOF).");
        disconnect(); // Connection closed
        return std::nullopt;
    } else { // received_len < 0
        LOG_ERROR("WazuhDbFimInterface: Failed to receive response from wazuh-db: {}.", strerror(errno));
        disconnect(); // Assume connection error
        return std::nullopt;
    }
}

std::optional<std::string> WazuhDbFimInterface::getBaselineEntry(const std::string& agentId, const std::string& filePath)
{
    // Command format: "agent [agent_id] syscheck load [filePath]"
    std::string command = "agent " + agentId + " syscheck load " + filePath;
    if (!sendCommand(command)) return std::nullopt;
    
    auto response = receiveResponse();
    if (response && response->rfind("ok ", 0) == 0) { // response starts with "ok "
        return response->substr(3); // Return the part after "ok "
    } else if (response && response->rfind("err ", 0) == 0) {
        LOG_WARN("WazuhDbFimInterface: Error from wazuh-db for getBaselineEntry: {}", *response);
        return std::nullopt; // Entry not found or other error
    }
    // If no response or unexpected format, it's an error (logged in receiveResponse or sendCommand)
    return std::nullopt;
}

bool WazuhDbFimInterface::storeEntryJson(const std::string& agentId, const std::string& fimJsonPayload)
{
    // Command format: "agent [agent_id] syscheck save2 [fimJsonPayload]"
    // The payload itself is JSON, so it might contain spaces.
    // wazuh-db command parser needs to handle this (usually it does for the last argument).
    std::string command = "agent " + agentId + " syscheck save2 " + fimJsonPayload;
    if (!sendCommand(command)) return false;

    auto response = receiveResponse();
    if (response && *response == "ok") {
        return true;
    }
    LOG_WARN("WazuhDbFimInterface: Failed to store JSON entry. Response: {}", response.value_or("N/A"));
    return false;
}

bool WazuhDbFimInterface::storeEntryLegacy(const std::string& agentId, const std::string& entryType, const std::string& checksumStringWithMeta, const std::string& filePath)
{
    // Command format: "agent [agent_id] syscheck save [entryType] [checksumStringWithMeta] [filePath]"
    // Ensure parts are correctly quoted or handled if they contain spaces, though typically filePath is last.
    // For this PoC, assuming no spaces in entryType or checksumStringWithMeta that would break parsing.
    std::string command = "agent " + agentId + " syscheck save " + entryType + " " + checksumStringWithMeta + " " + filePath;
    if (!sendCommand(command)) return false;

    auto response = receiveResponse();
     if (response && *response == "ok") {
        return true;
    }
    LOG_WARN("WazuhDbFimInterface: Failed to store legacy entry. Response: {}", response.value_or("N/A"));
    return false;
}

bool WazuhDbFimInterface::deleteEntry(const std::string& agentId, const std::string& filePathOrHash)
{
    // Command format: "agent [agent_id] syscheck delete [filePathOrHash]"
    std::string command = "agent " + agentId + " syscheck delete " + filePathOrHash;
    if (!sendCommand(command)) return false;

    auto response = receiveResponse();
    if (response && *response == "ok") {
        return true;
    }
    LOG_WARN("WazuhDbFimInterface: Failed to delete entry. Response: {}", response.value_or("N/A"));
    return false;
}

bool WazuhDbFimInterface::updateScanTimestamp(const std::string& agentId, FIMScanType scanType, int64_t timestamp)
{
    // Command format: "agent [agent_id] syscheck scan_info_update [scanTypeStr] [timestamp]"
    std::string scanTypeStr = scanTypeToString(scanType);
    std::string command = "agent " + agentId + " syscheck scan_info_update " + scanTypeStr + " " + std::to_string(timestamp);
    if (!sendCommand(command)) return false;
    
    auto response = receiveResponse();
    if (response && *response == "ok") {
        return true;
    }
    LOG_WARN("WazuhDbFimInterface: Failed to update scan timestamp. Response: {}", response.value_or("N/A"));
    return false;
}

} // namespace wazuh::engine::fim_handler
