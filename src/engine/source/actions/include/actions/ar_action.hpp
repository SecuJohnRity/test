#ifndef ENGINE_AR_ACTION_HPP
#define ENGINE_AR_ACTION_HPP

#include <string>
#include <base/baseTypes.hpp> // For base::Event

namespace wazuh::engine::actions
{

/**
 * @brief Formats an Active Response message and sends it to wazuh-execd.
 *
 * @param ar_command_name The name of the AR command/script to execute (e.g., "poc-ar-script").
 * @param triggering_event The event that triggered this action.
 * @param execd_queue_path The path to the wazuh-execd message queue.
 * @return bool True if the message was successfully sent (or queued), false otherwise.
 */
bool handle_trigger_active_response_action(
    const std::string& ar_command_name,
    const base::Event& triggering_event,
    const std::string& execd_queue_path);

} // namespace wazuh::engine::actions

#endif // ENGINE_AR_ACTION_HPP
