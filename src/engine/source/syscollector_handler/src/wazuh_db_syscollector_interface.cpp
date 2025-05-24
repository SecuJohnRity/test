#include "syscollector_handler/wazuh_db_syscollector_interface.hpp"
#include <base/logging.hpp>
#include <base/json.hpp> // For parsing input JSON if methods take json::Json

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h> // For close, sleep
#include <cerrno>
#include <cstring> // For strerror, strncpy, strtok_r
#include <vector>
#include <sstream> // For std::ostringstream

// Wazuh C library includes for socket operations and paths
extern "C" {
    #include "shared/defs.h"      // For WDB_LOCAL_SOCK, OS_MAXSTR
    #include "os_net/os_net.h"    // For OS_ConnectUnixDomain, OS_SendSecureTCP, OS_RecvSecureTCP, OS_CloseSocket
    // Note: wazuhdb_op.h is not typically included directly for socket commands.
}

// Fallback if WDB_LOCAL_SOCK is not in defs.h (it should be)
#ifndef WDB_LOCAL_SOCK
#define WDB_LOCAL_SOCK "queue/db/wdb"
#endif

namespace wazuh::engine::syscollector_handler
{

// Constructor and Destructor
WazuhDbSyscollectorInterface::WazuhDbSyscollectorInterface(std::string wazuh_db_socket_path)
    : m_socket_path(std::move(wazuh_db_socket_path)), m_socket_fd(-1)
{
    if (m_socket_path.empty()) {
        char wazuh_path[OS_MAXSTR];
        if (getenv("WAZUH_HOME") != NULL) {
            snprintf(wazuh_path, sizeof(wazuh_path), "%s/%s", getenv("WAZUH_HOME") , WDB_LOCAL_SOCK);
            m_socket_path = wazuh_path;
        } else {
            m_socket_path = "/" + std::string(WDB_LOCAL_SOCK); 
        }
    }
    LOG_INFO("WazuhDbSyscollectorInterface: Initialized for wazuh-db socket path '{}'.", m_socket_path);
}

WazuhDbSyscollectorInterface::~WazuhDbSyscollectorInterface()
{
    disconnect();
}

// Connection Management
bool WazuhDbSyscollectorInterface::connect()
{
    if (m_socket_fd >= 0) {
        LOG_WARN("WazuhDbSyscollectorInterface: Already connected.");
        return true;
    }
    m_socket_fd = OS_ConnectUnixDomain(m_socket_path.c_str(), SOCK_STREAM, OS_MAXSTR);
    if (m_socket_fd < 0) {
        LOG_ERROR("WazuhDbSyscollectorInterface: Failed to connect to wazuh-db socket '{}': {}.", m_socket_path, strerror(errno));
        return false;
    }
    LOG_INFO("WazuhDbSyscollectorInterface: Successfully connected to wazuh-db socket '{}' (fd: {}).", m_socket_path, m_socket_fd);
    return true;
}

void WazuhDbSyscollectorInterface::disconnect()
{
    if (m_socket_fd >= 0) {
        OS_CloseSocket(m_socket_fd);
        m_socket_fd = -1;
        LOG_INFO("WazuhDbSyscollectorInterface: Disconnected from wazuh-db socket '{}'.", m_socket_path);
    }
}

// Command Sending and Receiving
bool WazuhDbSyscollectorInterface::sendCommand(const std::string& command)
{
    if (m_socket_fd < 0) {
        LOG_ERROR("WazuhDbSyscollectorInterface: Not connected. Cannot send command: {}", command);
        return false;
    }
    LOG_DEBUG("WazuhDbSyscollectorInterface: Sending command: {}", command);
    if (OS_SendSecureTCP(m_socket_fd, command.length(), command.c_str()) != 0) {
        LOG_ERROR("WazuhDbSyscollectorInterface: Failed to send command '{}' to wazuh-db: {}.", command, strerror(errno));
        disconnect(); 
        return false;
    }
    return true;
}

std::optional<std::string> WazuhDbSyscollectorInterface::receiveResponse()
{
    if (m_socket_fd < 0) {
        LOG_ERROR("WazuhDbSyscollectorInterface: Not connected. Cannot receive response.");
        return std::nullopt;
    }
    char buffer[OS_MAXSTR + 1]; 
    int received_len = OS_RecvSecureTCP(m_socket_fd, buffer, OS_MAXSTR);
    if (received_len > 0) {
        buffer[received_len] = '\0';
        LOG_DEBUG("WazuhDbSyscollectorInterface: Received response: {}", buffer);
        return std::string(buffer);
    } else if (received_len == 0) {
        LOG_WARN("WazuhDbSyscollectorInterface: wazuh-db socket closed connection (EOF).");
        disconnect(); 
        return std::nullopt;
    } else { 
        LOG_ERROR("WazuhDbSyscollectorInterface: Failed to receive response from wazuh-db: {}.", strerror(errno));
        disconnect(); 
        return std::nullopt;
    }
}

// --- JSON to Pipe-Delimited Formatters ---
// These are simplified; real implementation needs careful field ordering and escaping.

std::string WazuhDbSyscollectorInterface::formatPackageForDb(const json::Json& pkgJson) const {
    std::ostringstream oss;
    // Example: name|version|architecture|format|vendor|source|install_time|checksum|item_id|multiarch_foreign|priority|section
    oss << pkgJson.getString("/name").value_or("-") << "|"
        << pkgJson.getString("/version").value_or("-") << "|"
        << pkgJson.getString("/architecture").value_or("-") << "|"
        << pkgJson.getString("/format").value_or("-") << "|"
        // ... add all relevant fields in the exact order wazuh-db expects for 'package save'
        << pkgJson.getString("/vendor").value_or("-"); 
    return oss.str();
}

std::string WazuhDbSyscollectorInterface::formatPortForDb(const json::Json& portJson) const {
    std::ostringstream oss;
    // Example: iface|protocol|local_ip|local_port|remote_ip|remote_port|tx_queue|rx_queue|inode|state|process_id|process_name
    oss << portJson.getString("/iface").value_or("-") << "|"
        << portJson.getString("/protocol").value_or("-") << "|"
        << portJson.getString("/local_ip").value_or("-") << "|"
        << portJson.getInt("/local_port").value_or(0) << "|"
        // ... add all relevant fields
        << portJson.getString("/process_name").value_or("-");
    return oss.str();
}

std::string WazuhDbSyscollectorInterface::formatProcessForDb(const json::Json& procJson) const {
    std::ostringstream oss;
    // Example: pid|name|state|ppid|utime|stime|cmd|euser|egroup|euid|egid|fgroup|fgid|priority|nice|nlwp|pgrp|session|start_time|processor|resident|size|vm_size|share
    oss << procJson.getInt("/pid").value_or(0) << "|"
        << procJson.getString("/name").value_or("-") << "|"
        // ... add all relevant fields
        << procJson.getInt("/vm_size").value_or(0);
    return oss.str();
}

std::string WazuhDbSyscollectorInterface::formatOsInfoForDb(const json::Json& osInfoJson) const {
    std::ostringstream oss;
    // Example: os_name|os_version|os_codename|os_major|os_minor|os_patch|os_build|os_platform|sysname|release|hostname|architecture|os_display_version
    oss << osInfoJson.getString("/os_name").value_or("-") << "|"
        << osInfoJson.getString("/os_version").value_or("-") << "|"
        // ... add all relevant fields
        << osInfoJson.getString("/architecture").value_or("-");
    return oss.str();
}

std::string WazuhDbSyscollectorInterface::formatHardwareInfoForDb(const json::Json& hwInfoJson) const {
     std::ostringstream oss;
    // Example: board_serial|cpu_cores|cpu_mhz|cpu_name|ram_free|ram_total|ram_usage|board_manufacturer|board_name|board_version
    oss << hwInfoJson.getString("/board_serial").value_or("-") << "|"
        << hwInfoJson.getInt("/cpu_cores").value_or(0) << "|"
        // ... add all relevant fields
        << hwInfoJson.getInt("/ram_total").value_or(0);
    return oss.str();
}

std::string WazuhDbSyscollectorInterface::formatNetworkInterfaceForDb(const json::Json& netIfaceJson) const {
    std::ostringstream oss;
    // Example: name|adapter|type|state|mtu|mac|tx_packets|rx_packets|tx_bytes|rx_bytes|tx_errors|rx_errors|tx_dropped|rx_dropped
    oss << netIfaceJson.getString("/name").value_or("-") << "|"
        << netIfaceJson.getString("/adapter").value_or("-") << "|"
        // ... add all relevant fields
        << netIfaceJson.getInt("/rx_dropped").value_or(0);
    return oss.str();
}

std::string WazuhDbSyscollectorInterface::formatNetworkAddressForDb(const json::Json& netAddrJson, bool isIpv4) const {
    std::ostringstream oss;
    // Example: address|broadcast|netmask (for ipv4) or prefix (for ipv6)
    oss << netAddrJson.getString(isIpv4 ? "/address" : "/address6").value_or("-") << "|"
        << netAddrJson.getString(isIpv4 ? "/broadcast" : "/broadcast6").value_or("-") << "|"
        << netAddrJson.getString(isIpv4 ? "/netmask" : "/prefixlen").value_or("-"); // Note: prefixlen for IPv6
    return oss.str();
}
std::string WazuhDbSyscollectorInterface::formatNetworkProtocolForDb(const json::Json& netProtoJson) const {
    std::ostringstream oss;
    // Example: iface|type|gateway|dhcp
    oss << netProtoJson.getString("/iface").value_or("-") << "|"
        << netProtoJson.getString("/type").value_or("-") << "|" // ipv4 or ipv6
        // ... add all relevant fields
        << netProtoJson.getString("/dhcp").value_or("-");
    return oss.str();
}


// --- Public Method Implementations ---

bool WazuhDbSyscollectorInterface::storePackage(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& packageJson) {
    std::string formatted_data = formatPackageForDb(packageJson);
    std::string command = "agent " + agentId + " package save " + std::to_string(scanId) + " " + scanTime + " " + formatted_data;
    if (!sendCommand(command)) return false;
    auto response = receiveResponse();
    return response && *response == "ok";
}

bool WazuhDbSyscollectorInterface::storePort(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& portJson) {
    std::string formatted_data = formatPortForDb(portJson);
    std::string command = "agent " + agentId + " port save " + std::to_string(scanId) + " " + scanTime + " " + formatted_data;
    if (!sendCommand(command)) return false;
    auto response = receiveResponse();
    return response && *response == "ok";
}

bool WazuhDbSyscollectorInterface::storeProcess(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& processJson) {
    std::string formatted_data = formatProcessForDb(processJson);
    std::string command = "agent " + agentId + " process save " + std::to_string(scanId) + " " + scanTime + " " + formatted_data;
    if (!sendCommand(command)) return false;
    auto response = receiveResponse();
    return response && *response == "ok";
}

bool WazuhDbSyscollectorInterface::storeOsInfo(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& osInfoJson) {
    std::string formatted_data = formatOsInfoForDb(osInfoJson);
    std::string command = "agent " + agentId + " osinfo save " + std::to_string(scanId) + " " + scanTime + " " + formatted_data;
    if (!sendCommand(command)) return false;
    auto response = receiveResponse();
    return response && *response == "ok";
}

bool WazuhDbSyscollectorInterface::storeHardwareInfo(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& hwInfoJson) {
    std::string formatted_data = formatHardwareInfoForDb(hwInfoJson);
    std::string command = "agent " + agentId + " hardware save " + std::to_string(scanId) + " " + scanTime + " " + formatted_data;
    if (!sendCommand(command)) return false;
    auto response = receiveResponse();
    return response && *response == "ok";
}

bool WazuhDbSyscollectorInterface::storeNetworkInterface(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& netIfaceJson) {
    std::string formatted_data = formatNetworkInterfaceForDb(netIfaceJson);
    std::string command = "agent " + agentId + " netiface save " + std::to_string(scanId) + " " + scanTime + " " + formatted_data;
    if (!sendCommand(command)) return false;
    auto response = receiveResponse();
    return response && *response == "ok";
}

bool WazuhDbSyscollectorInterface::storeNetworkAddress(const std::string& agentId, int scanId, const std::string& scanTime, 
                                                     const std::string& ifaceName, const json::Json& netAddrJson, bool isIpv4) {
    std::string formatted_data = formatNetworkAddressForDb(netAddrJson, isIpv4);
    std::string ip_version_flag = isIpv4 ? "ipv4" : "ipv6";
    std::string command = "agent " + agentId + " netaddr save " + std::to_string(scanId) + " " + scanTime + " " 
                        + ifaceName + " " + ip_version_flag + " " + formatted_data;
    if (!sendCommand(command)) return false;
    auto response = receiveResponse();
    return response && *response == "ok";
}

bool WazuhDbSyscollectorInterface::storeNetworkProtocol(const std::string& agentId, int scanId, const std::string& scanTime, 
                                                      const std::string& ifaceName, const json::Json& netProtoJson, bool isIpv4) {
    std::string formatted_data = formatNetworkProtocolForDb(netProtoJson);
    std::string ip_version_flag = isIpv4 ? "ipv4" : "ipv6";
    std::string command = "agent " + agentId + " netproto save " + std::to_string(scanId) + " " + scanTime + " " 
                        + ifaceName + " " + ip_version_flag + " " + formatted_data;
    if (!sendCommand(command)) return false;
    auto response = receiveResponse();
    return response && *response == "ok";
}


bool WazuhDbSyscollectorInterface::deleteOldInventory(const std::string& agentId, const std::string& inventoryType, int currentScanId, const std::string& scanTime) {
    // Command format: "agent [agent_id] [inventoryType] del [current_scan_id] [scan_time]"
    // inventoryType could be: package, port, process, osinfo, hardware, netiface, netaddr, netproto
    std::string command = "agent " + agentId + " " + inventoryType + " del " + std::to_string(currentScanId) + " " + scanTime;
    if (!sendCommand(command)) return false;
    auto response = receiveResponse();
    return response && *response == "ok";
}

} // namespace wazuh::engine::syscollector_handler
