#ifndef WAZUH_ENGINE_WAZUH_MQ_READER_HPP
#define WAZUH_ENGINE_WAZUH_MQ_READER_HPP

#include <string>
#include <optional>
#include <memory>
#include <vector> // For buffer

// Forward declare if necessary, or include actual Wazuh headers in .cpp
// For .hpp, it's better to keep dependencies minimal if possible.

namespace wazuh::engine::input_adapters
{

class WazuhMqReader
{
public:
    /**
     * @brief Constructor.
     * @param queue_path Path to the Wazuh message queue (e.g., "/queue/alerts/execq").
     * @param queue_name_for_logging A descriptive name for logging purposes (e.g., "EXECQUEUE").
     */
    WazuhMqReader(std::string queue_path, std::string queue_name_for_logging);

    /**
     * @brief Destructor. Ensures the queue is disconnected.
     */
    ~WazuhMqReader();

    // Disable copy and move semantics
    WazuhMqReader(const WazuhMqReader&) = delete;
    WazuhMqReader& operator=(const WazuhMqReader&) = delete;
    WazuhMqReader(WazuhMqReader&&) = delete;
    WazuhMqReader& operator=(WazuhMqReader&&) = delete;

    /**
     * @brief Connects to the Wazuh message queue.
     * @return True if connection was successful, false otherwise.
     */
    bool connect();

    /**
     * @brief Reads a message from the queue with a timeout.
     * Uses select() for timeout before calling OS_RecvUnix().
     * @param timeout_ms Timeout for reading in milliseconds.
     * @return An optional string containing the message if read successfully within timeout, 
     *         std::nullopt on timeout or if no data/error.
     */
    std::optional<std::string> readMessage(int timeout_ms = 100);

    /**
     * @brief Disconnects from the Wazuh message queue.
     */
    void disconnect();

    /**
     * @brief Checks if currently connected to the queue.
     * @return True if connected, false otherwise.
     */
    bool isConnected() const;

    /**
     * @brief Gets the name of the queue (for logging/identification).
     * @return The name of the queue.
     */
    const std::string& getQueueName() const;

    /**
     * @brief Gets the file descriptor of the queue.
     * @return The file descriptor, or -1 if not connected.
     */
    int getQueueFd() const;


private:
    std::string m_queue_path;
    std::string m_queue_name_for_logging;
    int m_queue_fd;
    bool m_is_connected;
    std::vector<char> m_buffer; // Buffer for reading messages

    // Using a common default size for Wazuh messages. OS_MAXSTR is 65536.
    // OS_RecvUnix typically takes OS_MAXSTR as buffer size.
    static constexpr int DEFAULT_BUFFER_SIZE = 65536 + 1; // +1 for null terminator
};

} // namespace wazuh::engine::input_adapters

#endif // WAZUH_ENGINE_WAZUH_MQ_READER_HPP
