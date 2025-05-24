#include "fim_handler/fim_engine_processor.hpp"
#include <base/logging.hpp>
#include <base/json.hpp> // For creating the base::Event

// For parsing legacy FIM strings, C string functions might be useful
#include <cstring> // For strncmp, strchr, etc.
#include <sstream> // For string splitting

namespace wazuh::engine::fim_handler
{

FimEngineProcessor::FimEngineProcessor(std::shared_ptr<WazuhDbFimInterface> db_interface)
    : m_db_interface(std::move(db_interface))
{
    if (!m_db_interface) {
        throw std::runtime_error("FimEngineProcessor: WazuhDbFimInterface is null.");
    }
}

// Simplified helper to trim whitespace
std::string trim_whitespace(const std::string& str) {
    const auto strBegin = str.find_first_not_of(" \t");
    if (strBegin == std::string::npos) return ""; // no content
    const auto strEnd = str.find_last_not_of(" \t");
    const auto strRange = strEnd - strBegin + 1;
    return str.substr(strBegin, strRange);
}

// Simplified parser for legacy FIM strings
// Example: "File: /etc/passwd, Size: 1234, Perm: 0644, Uid: 0, Gid: 0, Md5: ..., Sha1: ..., Sha256: ..."
// Example for whodata: "User: 'root', Program: '/usr/bin/passwd', PID: '1234'"
ParsedFimData FimEngineProcessor::parseFimPayload(const std::string& payload, const std::string& agent_id, const std::string& location) {
    ParsedFimData parsed_data;
    parsed_data.is_json_format = false; // Assume legacy unless JSON parsing succeeds

    // Attempt to parse as JSON first (for newer agent FIM events)
    // Newer FIM events from agents might be full JSON objects.
    // The `actual_log_payload` might be this JSON string.
    try {
        json::Json fim_json(payload.c_str()); // Attempt to parse the whole payload as JSON
        if (!fim_json.isNull() && fim_json.isObjectType()) {
            parsed_data.is_json_format = true;
            parsed_data.file_path = fim_json.getString("/path").value_or("");
            // Extract checksums
            parsed_data.md5 = fim_json.getString("/md5_sum"); // Or just md5
            parsed_data.sha1 = fim_json.getString("/sha1_sum");
            parsed_data.sha256 = fim_json.getString("/sha256_sum");
            // Combine primary checksum for legacy compatibility or direct use
            parsed_data.checksum = parsed_data.sha1.value_or(parsed_data.md5.value_or("")); 

            parsed_data.mtime = fim_json.getInt("/mtime");
            parsed_data.size = fim_json.getInt("/size_bytes"); // Or just size
            parsed_data.user_name = fim_json.getString("/uname");
            parsed_data.group_name = fim_json.getString("/gname");
            
            // Attributes string might be constructed or specific fields extracted
            std::stringstream attr_ss;
            attr_ss << "Perm: " << fim_json.getString("/perm").value_or("?");
            attr_ss << ", Uid: " << fim_json.getString("/uid").value_or(std::to_string(fim_json.getInt("/uid").value_or(-1)));
            attr_ss << ", Gid: " << fim_json.getString("/gid").value_or(std::to_string(fim_json.getInt("/gid").value_or(-1)));
            // Add more attributes as available and needed
            parsed_data.attributes = attr_ss.str();
            
            // Event type might be part of the JSON or inferred from context
            // For this PoC, assume it might be in a field like "/event_type" or needs inference
            parsed_data.event_type_str = fim_json.getString("/event_type").value_or("unknown"); 
                                                                             // e.g. "added", "modified", "deleted"
            LOG_DEBUG("FimEngineProcessor: Parsed FIM payload as JSON for agent '{}', path '{}'", agent_id, parsed_data.file_path);
            return parsed_data;
        }
    } catch (const std::exception& e) {
        LOG_DEBUG("FimEngineProcessor: Payload is not a valid JSON object for agent '{}', location '{}'. Attempting legacy parse. Error: {}", agent_id, location, e.what());
    }

    // If not JSON, proceed with legacy string parsing (highly simplified)
    // This is a very basic example and would need to be much more robust
    // to handle various legacy FIM string formats.
    // Example: "syscheck_new: /etc/testfilea md5:d41d8cd98f00b204e9800998ecf8427e,sha1:da39a3ee5e6b4b0d3255bfef95601890afd80709"
    // Example: "syscheck_update: /etc/testfilea attributes_changed" (whodata might follow)
    
    parsed_data.file_path = location; // In many legacy formats, location IS the file path.

    if (payload.rfind("syscheck_new: ", 0) == 0) {
        parsed_data.event_type_str = "added";
        // Simplified: assume path is location, and rest is checksums/attributes
        // A real parser would extract path from payload here too if available after "syscheck_new: "
        // For "syscheck_new: /path checksums", payload would be "/path checksums"
        std::string details = payload.substr(strlen("syscheck_new: "));
        trim_string_inplace(details);
        // Further parse 'details' for path and checksums.
        // This is where OS_DecodeFIMEntry logic would be complex.
        // For now, we assume 'location' is the primary path.
        parsed_data.attributes = details; // Placeholder
        parsed_data.checksum   = details; // Placeholder - needs actual checksum extraction
    } else if (payload.rfind("syscheck_update: ", 0) == 0) {
        parsed_data.event_type_str = "modified";
        parsed_data.attributes = payload.substr(strlen("syscheck_update: "));
        trim_string_inplace(parsed_data.attributes);
        // checksum might need to be fetched or might be part of attributes string
    } else if (payload.rfind("syscheck_delete: ", 0) == 0) {
        parsed_data.event_type_str = "deleted";
        // Path might be in payload after "syscheck_delete: "
        parsed_data.attributes = ""; // No attributes for deleted usually
    } else {
        // Could be whodata or other FIM related info not directly a file change event
        // For PoC, treat as "unknown" for now or try to extract basic info
        parsed_data.event_type_str = "unknown";
        parsed_data.attributes = payload; // Store raw payload as attributes
        LOG_DEBUG("FimEngineProcessor: Unrecognized legacy FIM payload format for agent '{}', location '{}'", agent_id, location);
    }
    
    LOG_DEBUG("FimEngineProcessor: Parsed FIM payload (legacy attempt) for agent '{}', path '{}', type '{}'", agent_id, parsed_data.file_path, parsed_data.event_type_str);
    return parsed_data;
}


FIMEventType FimEngineProcessor::compareWithBaseline(const ParsedFimData& current_data, 
                                                     const std::optional<std::string>& baseline_raw_data,
                                                     std::string& changed_attributes_details) {
    // This is a placeholder for actual comparison logic.
    // 1. If baseline_raw_data is std::nullopt (no baseline):
    //    - If current_data.event_type_str is "deleted", it's an error or anomaly.
    //    - Otherwise, it's an ADDED event.
    // 2. If baseline_raw_data exists:
    //    - Parse baseline_raw_data (it's a string from wazuh-db, format: "sha1 perm uid gid size mtime ...")
    //      into a structure comparable with ParsedFimData.
    //    - If current_data.event_type_str is "deleted", it's a DELETED event.
    //    - Compare checksums: if different, it's MODIFIED.
    //    - Compare attributes (permissions, owner, mtime, size): if different, it's MODIFIED.
    //      Populate changed_attributes_details string (e.g., "attributes_changed: perm old->new, size old->new").
    //    - If no differences, it's NO_CHANGE.

    changed_attributes_details = ""; // Clear it

    if (!baseline_raw_data.has_value()) {
        if (current_data.event_type_str == "deleted") {
            LOG_WARN("FimEngineProcessor: 'deleted' event for non-existent baseline: {}", current_data.file_path);
            return FIMEventType::NO_CHANGE; // Or a specific error type
        }
        changed_attributes_details = "New file";
        return FIMEventType::ADDED;
    }

    // Simplified: Assume baseline_raw_data is just the SHA1 checksum for comparison.
    // A real implementation needs to parse the full baseline string from wazuh-db.
    // Example baseline_raw_data: "da39a3ee5e6b4b0d3255bfef95601890afd80709 uid:0,gid:0,perm:100644 ..."
    
    std::string baseline_checksum = baseline_raw_data.value(); 
    // Crude extraction for PoC: assume checksum is the first space-separated token
    size_t first_space = baseline_checksum.find(' ');
    if (first_space != std::string::npos) {
        baseline_checksum = baseline_checksum.substr(0, first_space);
    }
    trim_string_inplace(baseline_checksum);

    if (current_data.event_type_str == "deleted") {
        changed_attributes_details = "File deleted";
        return FIMEventType::DELETED;
    }

    // Compare current checksum (prefer sha1 if available) with baseline
    std::string current_primary_checksum = current_data.sha1.value_or(current_data.checksum);
    trim_string_inplace(current_primary_checksum);

    if (current_primary_checksum != baseline_checksum) {
        changed_attributes_details = "Checksum changed. Old: " + baseline_checksum + ", New: " + current_primary_checksum;
        // Add more attribute comparison logic here
        return FIMEventType::MODIFIED;
    }
    
    // Add more detailed attribute comparison here if checksums match but attributes might differ
    // For PoC, if checksums match, assume NO_CHANGE or only attribute change if event_type_str suggests it.
    if (current_data.event_type_str == "modified") { // Agent might report modified due to mtime/attr change
        changed_attributes_details = "Attributes changed (checksums match)"; // Placeholder
        return FIMEventType::MODIFIED;
    }

    return FIMEventType::NO_CHANGE;
}

base::Event FimEngineProcessor::createFimAlertEvent(const input_adapters::CleanedMessageData& original_msg_meta,
                                                    const ParsedFimData& parsed_data, 
                                                    FIMEventType event_type,
                                                    const std::string& changed_attributes_details) {
    
    base::Event fim_alert_event = std::make_shared<json::Json>(json::JsonType::Object);

    // Standard fields from original message metadata
    fim_alert_event->setString(original_msg_meta.agent_id, "/agent/id");
    if (!original_msg_meta.agent_name.empty()) {
         fim_alert_event->setString(original_msg_meta.agent_name, "/agent/name");
    }
    if (!original_msg_meta.agent_ip.empty()) {
         fim_alert_event->setString(original_msg_meta.agent_ip, "/agent/ip");
    }
    // Use original raw message as part of the alert for full context
    fim_alert_event->setString(original_msg_meta.raw_full_message, "/input/raw_fim_message");


    // FIM specific fields
    fim_alert_event->setString(parsed_data.file_path, "/fim/path");
    
    std::string event_type_str;
    switch(event_type) {
        case FIMEventType::ADDED:    event_type_str = "added";    break;
        case FIMEventType::MODIFIED: event_type_str = "modified"; break;
        case FIMEventType::DELETED:  event_type_str = "deleted";  break;
        default:                     event_type_str = "unknown";  break;
    }
    fim_alert_event->setString(event_type_str, "/fim/event_type");
    
    if (!parsed_data.checksum.empty() && event_type != FIMEventType::DELETED) { // Checksum may not be relevant for deleted
        fim_alert_event->setString(parsed_data.checksum, "/fim/checksum_primary"); // Legacy combined or primary
    }
    if (parsed_data.md5.has_value()) fim_alert_event->setString(parsed_data.md5.value(), "/fim/md5");
    if (parsed_data.sha1.has_value()) fim_alert_event->setString(parsed_data.sha1.value(), "/fim/sha1");
    if (parsed_data.sha256.has_value()) fim_alert_event->setString(parsed_data.sha256.value(), "/fim/sha256");
    
    if (!parsed_data.attributes.empty()) {
        fim_alert_event->setString(parsed_data.attributes, "/fim/attributes_raw");
    }
    if (!changed_attributes_details.empty()) {
        fim_alert_event->setString(changed_attributes_details, "/fim/changes_detected");
    }

    // Add basic rule information (placeholders, actual rule matching is separate)
    fim_alert_event->setInt(510, "/rule/id"); // Example FIM rule ID
    fim_alert_event->setInt(7, "/rule/level"); // Example FIM rule level
    fim_alert_event->setString("FIM event processed by new engine.", "/rule/description");
    json::Json groups = json::Json::array();
    groups.add("syscheck"); // Common group for FIM
    groups.add("fim_event");
    fim_alert_event->set("/rule/groups", groups);

    // Add a timestamp (e.g., processing time)
    // This should ideally be the event time if available, or processing time.
    // For PoC, could use current time.
    // fim_alert_event->setInt(std::time(nullptr), "/timestamp_epoch");


    return fim_alert_event;
}


std::optional<base::Event> FimEngineProcessor::processFimMessage(const input_adapters::CleanedMessageData& msg)
{
    LOG_DEBUG("FimEngineProcessor: Processing FIM message for agent: {}, location: {}, payload: {}", 
              msg.agent_id, msg.location, msg.actual_log_payload);

    if (msg.agent_id.empty() || msg.actual_log_payload.empty()) {
        LOG_ERROR("FimEngineProcessor: Agent ID or FIM payload is empty. Cannot process.");
        return std::nullopt;
    }
    
    // 1. Parse the FIM payload (actual_log_payload from CleanedMessageData)
    //    The 'location' field from CleanedMessageData might be the file path for some legacy formats.
    ParsedFimData current_fim_data = parseFimPayload(msg.actual_log_payload, msg.agent_id, msg.location);
    if (current_fim_data.file_path.empty()) {
        LOG_WARN("FimEngineProcessor: Could not determine file path from FIM payload for agent: {}. Payload: {}", msg.agent_id, msg.actual_log_payload);
        return std::nullopt; // Cannot proceed without a file path
    }

    // 2. Connect to wazuh-db (WazuhDbFimInterface should handle reconnects if socket is bad)
    if (!m_db_interface->connect()) { // Ensure connected
        LOG_ERROR("FimEngineProcessor: Failed to connect to wazuh-db. Cannot process FIM event for agent: {}", msg.agent_id);
        return std::nullopt;
    }

    // 3. Get baseline entry from wazuh-db
    std::optional<std::string> baseline_raw_data = m_db_interface->getBaselineEntry(msg.agent_id, current_fim_data.file_path);

    // 4. Compare current FIM data with baseline
    std::string changed_attributes_details;
    FIMEventType event_type = compareWithBaseline(current_fim_data, baseline_raw_data, changed_attributes_details);

    // 5. Update/Store entry in wazuh-db based on event type
    bool db_update_ok = false;
    if (event_type == FIMEventType::ADDED || event_type == FIMEventType::MODIFIED) {
        if (current_fim_data.is_json_format) {
            // Re-serialize ParsedFimData to the JSON format expected by "save2" if necessary,
            // or assume original payload was JSON and store that if it's complete.
            // For PoC, we'll assume msg.actual_log_payload was the JSON if is_json_format is true.
            db_update_ok = m_db_interface->storeEntryJson(msg.agent_id, msg.actual_log_payload);
        } else {
            // Construct the legacy checksum string with metadata for storeEntryLegacy
            // This is complex; for PoC, we might just store the path and basic checksum.
            // Example: "sha1 perm uid gid size mtime ..."
            std::string legacy_checksum_meta = current_fim_data.checksum + " " + current_fim_data.attributes;
            db_update_ok = m_db_interface->storeEntryLegacy(msg.agent_id, "file", legacy_checksum_meta, current_fim_data.file_path);
        }
        if (!db_update_ok) {
            LOG_ERROR("FimEngineProcessor: Failed to store FIM entry in wazuh-db for agent: {}, path: {}", msg.agent_id, current_fim_data.file_path);
            // Decide if we should still generate an alert. For now, we will.
        }
    } else if (event_type == FIMEventType::DELETED) {
        db_update_ok = m_db_interface->deleteEntry(msg.agent_id, current_fim_data.file_path);
        if (!db_update_ok) {
            LOG_ERROR("FimEngineProcessor: Failed to delete FIM entry in wazuh-db for agent: {}, path: {}", msg.agent_id, current_fim_data.file_path);
        }
    } else { // NO_CHANGE
        db_update_ok = true; // No DB change needed
    }

    // 6. If an alertable event occurred, construct and return base::Event
    if (event_type != FIMEventType::NO_CHANGE) {
        // For PoC, generate alert even if DB update failed to see the event.
        // In production, this might depend on policy (e.g., alert if DB fails).
        LOG_INFO("FimEngineProcessor: FIM change detected for agent: {}, path: {}, type: {}", 
                 msg.agent_id, current_fim_data.file_path, static_cast<int>(event_type));
        return createFimAlertEvent(msg, current_fim_data, event_type, changed_attributes_details);
    }

    LOG_DEBUG("FimEngineProcessor: No alertable FIM change for agent: {}, path: {}", msg.agent_id, current_fim_data.file_path);
    return std::nullopt;
}

} // namespace wazuh::engine::fim_handler
