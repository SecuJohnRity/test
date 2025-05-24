#ifndef ENGINE_ROOTCHECK_ENGINE_PROCESSOR_HPP
#define ENGINE_ROOTCHECK_ENGINE_PROCESSOR_HPP

#include <string>
#include <optional>
#include <memory> // For std::shared_ptr

#include <base/event.hpp> // For base::Event (std::shared_ptr<json::Json>)
#include <input_adapters/wazuh_queue_reader.hpp> // For CleanedMessageData
#include "rootcheck_handler/wazuh_db_rootcheck_interface.hpp" // For WazuhDbRootcheckInterface

namespace wazuh::engine::rootcheck_handler
{

// Structure to hold parsed Rootcheck data (can be expanded)
struct ParsedRootcheckData {
    std::string message_title; // e.g., "System audit event." or "File integrity change."
    std::string pci_dss;
    std::string cis;
    std::string file_path; // If applicable
    std::string event_details; // Further details from the rootcheck log entry
    int level; // Rootcheck messages often have an associated level

    // Could also include fields like:
    // std::string old_value;
    // std::string new_value;
    // std::string remediation;

    ParsedRootcheckData() : level(0) {} // Default level
};


class RootcheckEngineProcessor
{
public:
    explicit RootcheckEngineProcessor(std::shared_ptr<WazuhDbRootcheckInterface> db_interface);

    /**
     * @brief Processes a Rootcheck message received from an input adapter.
     * 
     * This method will parse the Rootcheck data, interact with wazuh-db via WazuhDbRootcheckInterface
     * to store new findings, and then construct a base::Event (JSON) detailing the
     * rootcheck alert for further processing by the policy engine.
     * 
     * @param msg The cleaned message data containing agent_id and the Rootcheck payload.
     * @return std::optional<base::Event> A base::Event (JSON) if an alertable Rootcheck event occurred, 
     *                                     otherwise std::nullopt.
     */
    std::optional<base::Event> processRootcheckMessage(const input_adapters::CleanedMessageData& msg);

private:
    std::shared_ptr<WazuhDbRootcheckInterface> m_db_interface;

    // Private helper methods
    ParsedRootcheckData parseRootcheckPayload(const std::string& payload, const std::string& agent_id, const std::string& location);
    
    base::Event createRootcheckAlertEvent(const input_adapters::CleanedMessageData& original_msg_meta,
                                          const ParsedRootcheckData& parsed_data);
};

} // namespace wazuh::engine::rootcheck_handler

#endif // ENGINE_ROOTCHECK_ENGINE_PROCESSOR_HPP
