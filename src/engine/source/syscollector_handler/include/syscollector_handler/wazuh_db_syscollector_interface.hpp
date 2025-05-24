#ifndef ENGINE_WAZUH_DB_SYSCOLLECTOR_INTERFACE_HPP
#define ENGINE_WAZUH_DB_SYSCOLLECTOR_INTERFACE_HPP

#include <string>
#include <vector>
#include <optional>
#include <memory> // For std::shared_ptr

// Forward declare base::Json or include its header if methods directly take it
namespace json { class Json; } // Forward declaration

namespace wazuh::engine::syscollector_handler
{

class WazuhDbSyscollectorInterface
{
public:
    explicit WazuhDbSyscollectorInterface(std::string wazuh_db_socket_path);
    ~WazuhDbSyscollectorInterface();

    bool connect();
    void disconnect();

    // Methods to store different types of inventory data.
    // The json::Json& payload is the specific item (e.g., one package object, one port object).
    // scanId and scanTime are extracted from the overall Syscollector message.

    bool storePackage(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& packageJson);
    bool storePort(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& portJson);
    bool storeProcess(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& processJson);
    bool storeOsInfo(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& osInfoJson);
    bool storeHardwareInfo(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& hwInfoJson);
    bool storeNetworkInterface(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& netIfaceJson);
    
    // For network address and protocol, ifaceName is needed contextually for DB storage.
    // isIpv4 helps distinguish between IPv4 and IPv6 address/protocol structures if they differ in the JSON.
    bool storeNetworkAddress(const std::string& agentId, int scanId, const std::string& scanTime, 
                             const std::string& ifaceName, const json::Json& netAddrJson, bool isIpv4);
    bool storeNetworkProtocol(const std::string& agentId, int scanId, const std::string& scanTime, 
                              const std::string& ifaceName, const json::Json& netProtoJson); 

    /**
     * @brief Deletes entries from a previous scan that are no longer reported for a specific inventory type.
     * @param agentId The ID of the agent.
     * @param inventoryType The type of inventory to clean (e.g., "package", "port", "process").
     * @param currentScanId The ID of the current scan, used to identify older entries.
     * @param scanTime The timestamp of the current scan. (Note: wazuh-db 'del' command uses current_scan_id and scan_time of *current* scan)
     * @return True if the command was successfully sent and wazuh-db confirmed, false otherwise.
     */
    bool deleteOldInventory(const std::string& agentId, const std::string& inventoryType, int currentScanId, const std::string& scanTime);

private:
    std::string m_socket_path;
    int m_socket_fd;

    // Private helper methods for socket communication
    bool sendCommand(const std::string& command);
    std::optional<std::string> receiveResponse();

    // Helper methods to format JSON data into the pipe-delimited string format expected by wazuh-db
    // These need to be implemented carefully according to the specific wazuh-db command requirements for each type.
    std::string formatPackageForDb(const json::Json& packageJson) const;
    std::string formatPortForDb(const json::Json& portJson) const;
    std::string formatProcessForDb(const json::Json& processJson) const;
    std::string formatOsInfoForDb(const json::Json& osInfoJson) const;
    std::string formatHardwareInfoForDb(const json::Json& hwInfoJson) const;
    std::string formatNetworkInterfaceForDb(const json::Json& netIfaceJson) const;
    std::string formatNetworkAddressForDb(const json::Json& netAddrJson, bool isIpv4) const; 
    std::string formatNetworkProtocolForDb(const json::Json& netProtoJson) const;
};

} // namespace wazuh::engine::syscollector_handler

#endif // ENGINE_WAZUH_DB_SYSCOLLECTOR_INTERFACE_HPP
