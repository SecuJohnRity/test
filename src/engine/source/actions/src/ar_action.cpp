#include "actions/ar_action.hpp" // Corresponding header

#include <base/json.hpp>
#include <base/logging.hpp>

// Wazuh C library includes - Paths are relative to where CMake might be configured
// These paths might need adjustment based on the actual build environment setup
// and how Wazuh's C headers are exposed to the engine build.
extern "C" {
    // Assuming defs.h might contain EXECQUEUE or related constants.
    // If not, EXECQUEUE path will be hardcoded.
    #include "shared/defs.h" 
    #include "shared/mq_op.h"
    #include "os_net/os_net.h" // For OS_SendUnix, OS_CloseUnix
}

// Define EXECQUEUE if not available from headers (common default)
#ifndef EXECQUEUE
#define EXECQUEUE "/queue/alerts/execq"
#endif

namespace wazuh::engine::actions
{

// Forward declaration for an internal helper if needed, or make it static
// For now, direct implementation in handle_trigger_active_response_action

bool handle_trigger_active_response_action(
    const std::string& ar_command_name,
    const base::Event& triggering_event, /* std::shared_ptr<json::Json> */
    const std::string& execd_queue_path_param) {

    if (!triggering_event) {
        LOG_ERROR("AR_Action: Triggering event is null.");
        return false;
    }

    const std::string& execd_queue_path = execd_queue_path_param.empty() ? EXECQUEUE : execd_queue_path_param;

    LOG_DEBUG("AR_Action: Attempting to trigger AR command '{}' for event.", ar_command_name);

    // 1. Construct the JSON message for wazuh-execd
    json::Json execd_msg = json::Json::object();
    try {
        execd_msg.setString(ar_command_name, "/command");

        json::Json params = json::Json::object();
        json::Json alert_details = json::Json::object();

        // Populate alert_details from triggering_event
        alert_details.setString(triggering_event->getString("/agent_id").value_or("000"), "/agent/id");
        alert_details.setString(triggering_event->getString("/agent_name").value_or("unknown"), "/agent/name");
        alert_details.setString(triggering_event->getString("/agent_ip").value_or("127.0.0.1"), "/agent/ip"); // Assuming it exists

        // For PoC, hardcode some rule details if not easily available from the event
        // In a real system, these would come from the matched rule's metadata
        json::Json rule_details = json::Json::object();
        rule_details.setInt(triggering_event->getInt("/poc_alert/rule_id").value_or(100001), "/id");
        rule_details.setInt(triggering_event->getInt("/poc_alert/level").value_or(5), "/level");
        rule_details.setString(triggering_event->getString("/poc_alert/description").value_or("PoC AR Triggered"), "/description");
        // rule_details.setArray("/groups"); // Example: add groups if available
        // alert_details.setArray("/rule/groups"); // Example
        alert_details.set("/rule", rule_details);


        alert_details.setString(triggering_event->getString("/original_log").value_or(""), "/full_log");
        // Assuming location might be the agent ID for agent-originated events
        alert_details.setString(triggering_event->getString("/agent_id").value_or("unknown_location"), "/location");


        // Add other fields as per common AR message structure if available/needed
        // e.g., timestamp, etc. The original event is also embedded in the PoC alert.

        params.set("/alert", alert_details);
        
        json::Json origin_details = json::Json::object();
        origin_details.setString("wazuh-engine-poc", "/module");
        // origin_details.setString(hostname, "/name"); // If hostname is available
        params.set("/origin", origin_details);
        
        execd_msg.set("/parameters", params);

    } catch (const std::exception& e) {
        LOG_ERROR("AR_Action: Failed to construct JSON for execd: {}", e.what());
        return false;
    }
        
    std::string execd_json_string;
    try {
        execd_json_string = execd_msg.str(); // Get compact JSON string
    } catch (const std::exception& e) {
        LOG_ERROR("AR_Action: Failed to serialize JSON for execd: {}", e.what());
        return false;
    }

    LOG_DEBUG("AR_Action: Sending to execd queue '{}': {}", execd_queue_path, execd_json_string);

    // 2. Send the message to EXECQUEUE
    int mq_fd = -1;
    int attempts = 0;
    const int max_attempts = 3; // Try a few times

    // StartMQ returns a file descriptor (socket) for the queue
    // WRITE mode, 1 attempt to open.
    // For a persistent connection, this might be opened once and reused.
    // For AR, it's often opened/closed per message by analysisd.
    while (attempts < max_attempts) {
        mq_fd = StartMQ(execd_queue_path.c_str(), WRITE, 1); // 1 attempt to open
        if (mq_fd >= 0) {
            break;
        }
        attempts++;
        if (attempts < max_attempts) {
            LOG_WARN("AR_Action: Failed to open execd queue '{}' on attempt {}. Retrying...", execd_queue_path, attempts);
            sleep(1); // Wait a bit before retrying
        }
    }

    if (mq_fd < 0) {
        LOG_ERROR("AR_Action: Failed to open execd queue '{}' after {} attempts: {}", execd_queue_path, max_attempts, strerror(errno));
        return false;
    }

    // OS_SendUnix is used for sending messages to UNIX domain sockets used by Wazuh queues
    if (OS_SendUnix(mq_fd, execd_json_string.c_str(), execd_json_string.length()) < 0) {
        LOG_ERROR("AR_Action: Failed to send message to execd queue '{}': {}", execd_queue_path, strerror(errno));
        OS_CloseUnix(mq_fd); // Close the socket
        return false;
    }

    LOG_INFO("AR_Action: Successfully sent AR message to execd queue '{}' for command '{}'.", execd_queue_path, ar_command_name);
    OS_CloseUnix(mq_fd); // Close the socket
    return true;
}

} // namespace wazuh::engine::actions
