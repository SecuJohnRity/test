#ifndef ENGINE_WAZUH_DB_FIM_INTERFACE_HPP
#define ENGINE_WAZUH_DB_FIM_INTERFACE_HPP

#include <string>
#include <vector>
#include <optional>
#include <memory> // For std::shared_ptr

// For FIMScanType, define a simple enum for now
enum class FIMScanType {
    START_SCAN,
    END_SCAN,
    END_FIRST_SCAN
    // Add others if needed, e.g., REALTIME_SCAN_EVENT
};

namespace wazuh::engine::fim_handler
{

class WazuhDbFimInterface
{
public:
    explicit WazuhDbFimInterface(std::string wazuh_db_socket_path);
    ~WazuhDbFimInterface();

    bool connect();
    void disconnect();

    /**
     * @brief Retrieves a baseline FIM entry for a given agent and file path.
     * @param agentId The ID of the agent (e.g., "001", "local").
     * @param filePath The absolute path of the file to retrieve.
     * @return Raw string from wazuh-db (checksum string with metadata) or std::nullopt if not found/error.
     */
    std::optional<std::string> getBaselineEntry(const std::string& agentId, const std::string& filePath);

    /**
     * @brief Stores a new FIM entry from a JSON payload (typically from newer agents).
     * @param agentId The ID of the agent.
     * @param fimJsonPayload The FIM data as a JSON string.
     * @return True if wazuh-db confirms storage ("ok"), false otherwise.
     */
    bool storeEntryJson(const std::string& agentId, const std::string& fimJsonPayload);
    
    /**
     * @brief Stores a legacy FIM entry.
     * @param agentId The ID of the agent.
     * @param entryType Type of entry (e.g., "file", "registry_key", "registry_value").
     * @param checksumStringWithMeta The checksum string possibly including metadata like permissions, user, group etc.
     * @param filePath The file path or registry key path.
     * @return True if wazuh-db confirms storage ("ok"), false otherwise.
     */
    bool storeEntryLegacy(const std::string& agentId, const std::string& entryType, const std::string& checksumStringWithMeta, const std::string& filePath);

    /**
     * @brief Deletes a FIM entry.
     * @param agentId The ID of the agent.
     * @param filePathOrHash The file path or a specific hash to identify the entry for deletion.
     * @return True if wazuh-db confirms deletion ("ok"), false otherwise.
     */
    bool deleteEntry(const std::string& agentId, const std::string& filePathOrHash);

    /**
     * @brief Updates FIM scan timestamp information for an agent.
     * @param agentId The ID of the agent.
     * @param scanType The type of scan event (start, end, end_first).
     * @param timestamp The epoch timestamp for the scan event.
     * @return True if wazuh-db confirms update ("ok"), false otherwise.
     */
    bool updateScanTimestamp(const std::string& agentId, FIMScanType scanType, int64_t timestamp);
    
    // Other potential methods:
    // bool cleanAgentDb(const std::string& agentId);
    // bool updateEntryDate(const std::string& agentId, const std::string& filePathOrHash, int64_t newTimestamp);

private:
    std::string m_socket_path;
    int m_socket_fd;

    // Private helper methods for socket communication
    bool sendCommand(const std::string& command);
    std::optional<std::string> receiveResponse();
    std::string scanTypeToString(FIMScanType scanType) const; // Helper for updateScanTimestamp
};

} // namespace wazuh::engine::fim_handler

#endif // ENGINE_WAZUH_DB_FIM_INTERFACE_HPP
