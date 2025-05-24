#ifndef ENGINE_FIM_ENGINE_PROCESSOR_HPP
#define ENGINE_FIM_ENGINE_PROCESSOR_HPP

#include <string>
#include <optional>
#include <memory> // For std::shared_ptr

#include <base/event.hpp> // For base::Event (std::shared_ptr<json::Json>)
#include <input_adapters/wazuh_queue_reader.hpp> // For CleanedMessageData
#include "fim_handler/wazuh_db_fim_interface.hpp" // For WazuhDbFimInterface

namespace wazuh::engine::fim_handler
{

// Represents the type of FIM event detected (add, modify, delete)
enum class FIMEventType {
    ADDED,
    MODIFIED,
    DELETED,
    NO_CHANGE // For cases where an entry is processed but no alertable change is found
};

// Structure to hold parsed FIM data (can be expanded significantly)
struct ParsedFimData {
    std::string file_path;
    std::string checksum; // MD5, SHA1, SHA256 concatenated or just primary
    std::string attributes; // Permissions, UID, GID, modification time, etc. (raw or structured)
    std::string event_type_str; // "added", "modified", "deleted" from agent message
    bool is_json_format; // True if the payload was new JSON format

    // Fields specific to JSON format (optional, or use a variant)
    std::optional<std::string> md5;
    std::optional<std::string> sha1;
    std::optional<std::string> sha256;
    std::optional<int64_t> mtime;
    std::optional<int64_t> size;
    std::optional<std::string> user_name;
    std::optional<std::string> group_name;
    // Add more fields as needed from the JSON format

    ParsedFimData() : is_json_format(false) {}
};


class FimEngineProcessor
{
public:
    explicit FimEngineProcessor(std::shared_ptr<WazuhDbFimInterface> db_interface);

    /**
     * @brief Processes a FIM message received from an input adapter.
     * 
     * This method will parse the FIM data, interact with wazuh-db via WazuhDbFimInterface
     * to compare with baseline, store new/updated entries, and determine if an alert
     * should be generated.
     * 
     * @param msg The cleaned message data containing agent_id and the FIM payload.
     * @return std::optional<base::Event> A base::Event (JSON) if an alertable FIM event occurred, 
     *                                     otherwise std::nullopt.
     */
    std::optional<base::Event> processFimMessage(const input_adapters::CleanedMessageData& msg);

private:
    std::shared_ptr<WazuhDbFimInterface> m_db_interface;

    // Private helper methods
    ParsedFimData parseFimPayload(const std::string& payload, const std::string& agent_id, const std::string& location);
    
    // Helper to compare current (parsed) FIM data with baseline data from wazuh-db
    // Returns the type of event and potentially what changed.
    FIMEventType compareWithBaseline(const ParsedFimData& current_data, 
                                     const std::optional<std::string>& baseline_raw_data,
                                     std::string& changed_attributes_details); 
                                     // changed_attributes_details could be a string or structured data

    // Helper to construct the FIM alert event (JSON)
    base::Event createFimAlertEvent(const input_adapters::CleanedMessageData& original_msg_meta,
                                    const ParsedFimData& parsed_data, 
                                    FIMEventType event_type,
                                    const std::string& changed_attributes_details);
};

} // namespace wazuh::engine::fim_handler

#endif // ENGINE_FIM_ENGINE_PROCESSOR_HPP
