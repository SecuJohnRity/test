#include "syscollector_handler/syscollector_engine_processor.hpp"
#include <base/logging.hpp>
#include <base/json.hpp> // For parsing input JSON

#include <vector>

namespace wazuh::engine::syscollector_handler
{

SyscollectorEngineProcessor::SyscollectorEngineProcessor(std::shared_ptr<WazuhDbSyscollectorInterface> db_interface)
    : m_db_interface(std::move(db_interface))
{
    if (!m_db_interface) {
        throw std::runtime_error("SyscollectorEngineProcessor: WazuhDbSyscollectorInterface is null.");
    }
}

void SyscollectorEngineProcessor::processInventoryType(
    const std::string& agentId, 
    const std::string& inventoryType, 
    int scanId, 
    const std::string& scanTime, 
    const json::Json& inventoryData) // inventoryData is an array of items for this type
{
    LOG_DEBUG("SyscollectorEngineProcessor: Processing inventory type '{}' for agent '{}', scan_id {}, scan_time {}", 
              inventoryType, agentId, scanId, scanTime);

    if (!inventoryData.isArray()) {
        LOG_ERROR("SyscollectorEngineProcessor: Inventory data for type '{}' is not an array. Agent: {}", inventoryType, agentId);
        return;
    }

    for (const auto& item : inventoryData.asArray()) {
        if (!item.isObjectType()) {
            LOG_WARN("SyscollectorEngineProcessor: Skipping non-object item in inventory type '{}' for agent '{}'", inventoryType, agentId);
            continue;
        }
        
        bool success = false;
        if (inventoryType == "package" || inventoryType == "packages") { // "packages" for newer agents
            success = m_db_interface->storePackage(agentId, scanId, scanTime, item);
        } else if (inventoryType == "port" || inventoryType == "ports") {
            success = m_db_interface->storePort(agentId, scanId, scanTime, item);
        } else if (inventoryType == "process" || inventoryType == "processes") {
            success = m_db_interface->storeProcess(agentId, scanId, scanTime, item);
        } else if (inventoryType == "osinfo") { // osinfo is usually a single object, not an array in payload, handle in main parser
             LOG_WARN("SyscollectorEngineProcessor: OSInfo should be handled directly, not as array type. Agent: {}", agentId);
        } else if (inventoryType == "hardware") { // hardware is usually a single object
             LOG_WARN("SyscollectorEngineProcessor: HardwareInfo should be handled directly, not as array type. Agent: {}", agentId);
        } else if (inventoryType == "netiface" || inventoryType == "network_interfaces") {
            success = m_db_interface->storeNetworkInterface(agentId, scanId, scanTime, item);
            // Network addresses and protocols are often nested within interfaces
            if (item.exists("/addresses") && item.getJson("/addresses").isArray()) {
                for (const auto& addr : item.getJson("/addresses").asArray()) {
                    // Determine if ipv4 or ipv6 based on fields like addr.getString("/address") vs addr.getString("/address6")
                    // or a specific "type" field if present in the JSON from agent.
                    bool is_ipv4 = addr.exists("/address"); // Simple heuristic
                    m_db_interface->storeNetworkAddress(agentId, scanId, scanTime, item.getString("/name").value_or("unknown_iface"), addr, is_ipv4);
                }
            }
            if (item.exists("/protocol") && item.getJson("/protocol").isObjectType()){ // Assuming protocol is an object for each iface
                 m_db_interface->storeNetworkProtocol(agentId, scanId, scanTime, item.getString("/name").value_or("unknown_iface"), item.getJson("/protocol"));
            }

        } else {
            LOG_WARN("SyscollectorEngineProcessor: Unknown or unhandled inventory type '{}' for agent '{}'", inventoryType, agentId);
        }

        if (!success && inventoryType != "osinfo" && inventoryType != "hardware") { // Avoid double logging for types handled elsewhere
            LOG_ERROR("SyscollectorEngineProcessor: Failed to store item for inventory type '{}', agent '{}'", inventoryType, agentId);
        }
    }
}


void SyscollectorEngineProcessor::processSyscollectorMessage(const input_adapters::CleanedMessageData& msg)
{
    LOG_DEBUG("SyscollectorEngineProcessor: Processing message for agent: {}, location: {}, payload size: {}", 
              msg.agent_id, msg.location, msg.actual_log_payload.length());

    if (msg.agent_id.empty()) {
        LOG_ERROR("SyscollectorEngineProcessor: Agent ID is empty. Cannot process Syscollector message.");
        return;
    }
    if (msg.actual_log_payload.empty()) {
        LOG_ERROR("SyscollectorEngineProcessor: Payload is empty for agent: {}. Cannot process.", msg.agent_id);
        return;
    }

    json::Json syscollector_json;
    try {
        syscollector_json = json::Json(msg.actual_log_payload.c_str());
    } catch (const std::exception& e) {
        LOG_ERROR("SyscollectorEngineProcessor: Failed to parse Syscollector JSON payload for agent {}: {}. Payload: {}", 
                  msg.agent_id, e.what(), msg.actual_log_payload);
        return;
    }

    if (!syscollector_json.isObjectType()) {
        LOG_ERROR("SyscollectorEngineProcessor: Syscollector payload is not a JSON object for agent {}.", msg.agent_id);
        return;
    }

    // Extract common scan metadata
    // Example Syscollector message structure (can vary slightly):
    // { "type": "program", "ID": 1625080000, "timestamp": "2024-05-23T10:00:00Z", "data": [ {...}, ... ] }
    // or for single-item types:
    // { "type": "OS", "ID": 1625080000, "timestamp": "2024-05-23T10:00:00Z", "data": { ... } }
    
    std::string inventory_type_full = syscollector_json.getString("/type").value_or("");
    int scan_id = syscollector_json.getInt("/ID").value_or(0); // Or "/scan_id"
    std::string scan_time_str = syscollector_json.getString("/timestamp").value_or(""); // Agent timestamp of scan

    if (inventory_type_full.empty() || scan_id == 0 || scan_time_str.empty()) {
        LOG_ERROR("SyscollectorEngineProcessor: Missing type, ID, or timestamp in Syscollector payload for agent {}. Payload: {}", 
                  msg.agent_id, msg.actual_log_payload);
        return;
    }
    
    // Connect to DB (WazuhDbSyscollectorInterface should handle reconnect logic if connection drops)
    if (!m_db_interface->connect()) {
        LOG_ERROR("SyscollectorEngineProcessor: Failed to connect to wazuh-db. Cannot process syscollector event for agent: {}", msg.agent_id);
        return;
    }

    // Handle scan end events (deletion of old inventory)
    // e.g. "program_end", "port_end", "process_end"
    size_t end_suffix_pos = inventory_type_full.rfind("_end");
    if (end_suffix_pos != std::string::npos && end_suffix_pos > 0) {
        std::string inventory_type_base = inventory_type_full.substr(0, end_suffix_pos);
        LOG_INFO("SyscollectorEngineProcessor: Received scan end for type '{}', agent '{}'. Deleting old inventory.", 
                 inventory_type_base, msg.agent_id);
        if (!m_db_interface->deleteOldInventory(msg.agent_id, inventory_type_base, scan_id, scan_time_str)) {
            LOG_ERROR("SyscollectorEngineProcessor: Failed to delete old inventory for type '{}', agent '{}'.", 
                      inventory_type_base, msg.agent_id);
        }
        // No further processing for "_end" messages usually.
        return;
    }


    // Handle specific inventory types based on the "type" field
    // The "data" field can be an array or an object.
    if (!syscollector_json.exists("/data")) {
        LOG_ERROR("SyscollectorEngineProcessor: Missing 'data' field in Syscollector payload for agent {}. Type: {}", 
                  msg.agent_id, inventory_type_full);
        return;
    }
    const json::Json& inventory_data = syscollector_json.getJson("/data");

    if (inventory_type_full == "package" || inventory_type_full == "packages") {
        handlePackages(msg.agent_id, scan_id, scan_time_str, inventory_data);
    } else if (inventory_type_full == "port" || inventory_type_full == "ports") {
        handlePorts(msg.agent_id, scan_id, scan_time_str, inventory_data);
    } else if (inventory_type_full == "process" || inventory_type_full == "processes") {
        handleProcesses(msg.agent_id, scan_id, scan_time_str, inventory_data);
    } else if (inventory_type_full == "OS" || inventory_type_full == "osinfo") { // "OS" is common from agents
        handleOsInfo(msg.agent_id, scan_id, scan_time_str, inventory_data);
    } else if (inventory_type_full == "hardware" || inventory_type_full == "hardwareinfo") {
        handleHardwareInfo(msg.agent_id, scan_id, scan_time_str, inventory_data);
    } else if (inventory_type_full == "netiface" || inventory_type_full == "network_interfaces") {
        handleNetworkInterfaces(msg.agent_id, scan_id, scan_time_str, inventory_data);
    } else {
        LOG_WARN("SyscollectorEngineProcessor: Unhandled Syscollector inventory type '{}' for agent {}.", inventory_type_full, msg.agent_id);
    }
}

// --- Private Helper Implementations for specific types ---
// These take the array/object directly from the "data" field of the main payload.

void SyscollectorEngineProcessor::handlePackages(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& packagesArray) {
    if (!packagesArray.isArray()) { LOG_ERROR("Syscollector/Packages: Data is not an array for agent {}", agentId); return; }
    for (const auto& pkgJson : packagesArray.asArray()) {
        if (!pkgJson.isObjectType()) continue;
        m_db_interface->storePackage(agentId, scanId, scanTime, pkgJson);
    }
}

void SyscollectorEngineProcessor::handlePorts(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& portsArray) {
    if (!portsArray.isArray()) { LOG_ERROR("Syscollector/Ports: Data is not an array for agent {}", agentId); return; }
    for (const auto& portJson : portsArray.asArray()) {
        if (!portJson.isObjectType()) continue;
        m_db_interface->storePort(agentId, scanId, scanTime, portJson);
    }
}

void SyscollectorEngineProcessor::handleProcesses(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& processesArray) {
    if (!processesArray.isArray()) { LOG_ERROR("Syscollector/Processes: Data is not an array for agent {}", agentId); return; }
    for (const auto& procJson : processesArray.asArray()) {
        if (!procJson.isObjectType()) continue;
        m_db_interface->storeProcess(agentId, scanId, scanTime, procJson);
    }
}

void SyscollectorEngineProcessor::handleOsInfo(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& osInfoObject) {
    if (!osInfoObject.isObjectType()) { LOG_ERROR("Syscollector/OSInfo: Data is not an object for agent {}", agentId); return; }
    m_db_interface->storeOsInfo(agentId, scanId, scanTime, osInfoObject);
}

void SyscollectorEngineProcessor::handleHardwareInfo(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& hwInfoObject) {
    if (!hwInfoObject.isObjectType()) { LOG_ERROR("Syscollector/Hardware: Data is not an object for agent {}", agentId); return; }
    m_db_interface->storeHardwareInfo(agentId, scanId, scanTime, hwInfoObject);
}

void SyscollectorEngineProcessor::handleNetworkInterfaces(const std::string& agentId, int scanId, const std::string& scanTime, const json::Json& netIfacesArray) {
    if (!netIfacesArray.isArray()) { LOG_ERROR("Syscollector/NetIF: Data is not an array for agent {}", agentId); return; }
    for (const auto& ifaceJson : netIfacesArray.asArray()) {
        if (!ifaceJson.isObjectType()) continue;
        std::string ifaceName = ifaceJson.getString("/name").value_or("unknown_iface");
        m_db_interface->storeNetworkInterface(agentId, scanId, scanTime, ifaceJson);

        if (ifaceJson.exists("/ipv4_addresses") && ifaceJson.getJson("/ipv4_addresses").isArray()) {
            for (const auto& addrJson : ifaceJson.getJson("/ipv4_addresses").asArray()) {
                m_db_interface->storeNetworkAddress(agentId, scanId, scanTime, ifaceName, addrJson, true);
            }
        }
        if (ifaceJson.exists("/ipv6_addresses") && ifaceJson.getJson("/ipv6_addresses").isArray()) {
            for (const auto& addrJson : ifaceJson.getJson("/ipv6_addresses").asArray()) {
                 m_db_interface->storeNetworkAddress(agentId, scanId, scanTime, ifaceName, addrJson, false);
            }
        }
        // Assuming protocol info is directly under the interface object
        if (ifaceJson.exists("/type") && ifaceJson.exists("/gateway")) { // Heuristic for protocol info
             m_db_interface->storeNetworkProtocol(agentId, scanId, scanTime, ifaceName, ifaceJson);
        }
    }
}

} // namespace wazuh::engine::syscollector_handler
