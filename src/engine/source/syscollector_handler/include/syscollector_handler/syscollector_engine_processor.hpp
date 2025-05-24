#ifndef ENGINE_SYSCOLLECTOR_ENGINE_PROCESSOR_HPP
#define ENGINE_SYSCOLLECTOR_ENGINE_PROCESSOR_HPP

#include <string>
#include <memory> // For std::shared_ptr

#include <input_adapters/wazuh_queue_reader.hpp> // For CleanedMessageData
#include "syscollector_handler/wazuh_db_syscollector_interface.hpp" // For WazuhDbSyscollectorInterface

// Forward declare json::Json
namespace json { class Json; }

namespace wazuh::engine::syscollector_handler
{

class SyscollectorEngineProcessor
{
public:
    explicit SyscollectorEngineProcessor(std::shared_ptr<WazuhDbSyscollectorInterface> db_interface);

    /**
     * @brief Processes a Syscollector message received from an input adapter.
     * 
     * This method will parse the Syscollector JSON data from the agent,
     * extract inventory type, scan metadata, and individual inventory items.
     * It then uses WazuhDbSyscollectorInterface to store this data in wazuh-db.
     * For "_end" scan types, it triggers deletion of old inventory.
     * 
     * @param msg The cleaned message data containing agent_id and the Syscollector JSON payload.
     */
    void processSyscollectorMessage(const input_adapters::CleanedMessageData& msg);

private:
    std::shared_ptr<WazuhDbSyscollectorInterface> m_db_interface;

    // Private helper methods
    void processInventoryType(const std::string& agentId, const std::string& inventoryType, 
                              int scanId, const std::string& scanTime, 
                              const json::Json& inventoryData);
    
    // Specific handlers for each inventory type within the main JSON payload
    void handlePackages(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& packagesArray);
    void handlePorts(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& portsArray);
    void handleProcesses(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& processesArray);
    void handleOsInfo(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& osInfoObject);
    void handleHardwareInfo(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& hwInfoObject);
    void handleNetworkInterfaces(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& netIfacesArray);
    // Network Address and Protocol are often nested within Network Interfaces in Syscollector JSON
    // So, they might be called from handleNetworkInterfaces.
};

} // namespace wazuh::engine::syscollector_handler

#endif // ENGINE_SYSCOLLECTOR_ENGINE_PROCESSOR_HPP
