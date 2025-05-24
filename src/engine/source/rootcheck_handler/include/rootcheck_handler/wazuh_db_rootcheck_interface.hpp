#ifndef ENGINE_WAZUH_DB_ROOTCHECK_INTERFACE_HPP
#define ENGINE_WAZUH_DB_ROOTCHECK_INTERFACE_HPP

#include <string>
#include <vector>
#include <optional>
#include <memory> // For std::shared_ptr

// Forward declare json::Json if payloads are directly handled as such
namespace json { class Json; }

namespace wazuh::engine::rootcheck_handler
{

class WazuhDbRootcheckInterface
{
public:
    explicit WazuhDbRootcheckInterface(std::string wazuh_db_socket_path);
    ~WazuhDbRootcheckInterface();

    bool connect();
    void disconnect();

    /**
     * @brief Stores a new rootcheck entry/finding.
     *        Rootcheck data from agents is often JSON, but wazuh-db interaction might be field-based.
     *        This method assumes the processor will format data as needed by wazuh-db.
     * @param agentId The ID of the agent.
     * @param rootcheckData A string representing the processed rootcheck data for storage.
     *                      This could be a direct JSON payload if wazuh-db supports it,
     *                      or a specially formatted string for legacy commands.
     * @return True if wazuh-db confirms storage ("ok"), false otherwise.
     */
    bool storeRootcheckEntry(const std::string& agentId, const std::string& rootcheckData);

    // Rootcheck doesn't typically baseline individual entries like FIM.
    // It's more about reporting current findings. A baseline might exist for "last scan".
    // For PoC, getRootcheckBaseline is omitted as its direct utility is less clear than for FIM.
    // If needed, it would fetch the last scan's state or specific entries.

    /**
     * @brief Clears all rootcheck data for a specific agent.
     *        This is typically done at the start of a new rootcheck scan.
     * @param agentId The ID of the agent.
     * @return True if wazuh-db confirms clearance ("ok"), false otherwise.
     */
    bool clearAgentRootcheck(const std::string& agentId);
    
    /**
     * @brief Updates the timestamp of the last rootcheck scan for an agent.
     * @param agentId The ID of the agent.
     * @param timestamp The epoch timestamp for the scan event (typically scan end).
     * @return True if wazuh-db confirms update ("ok"), false otherwise.
     */
    bool updateLastScan(const std::string& agentId, int64_t timestamp);


private:
    std::string m_socket_path;
    int m_socket_fd;

    // Private helper methods for socket communication
    bool sendCommand(const std::string& command);
    std::optional<std::string> receiveResponse();
};

} // namespace wazuh::engine::rootcheck_handler

#endif // ENGINE_WAZUH_DB_ROOTCHECK_INTERFACE_HPP
