#ifndef ENGINE_WAZUH_QUEUE_READER_HPP
#define ENGINE_WAZUH_QUEUE_READER_HPP

#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <functional>
#include <optional> // For optional timestamp

// Forward declaration for WazuhMessageCleaner output struct
namespace wazuh::engine::input_adapters {
    struct CleanedMessageData; 
}

namespace wazuh::engine::input_adapters
{

enum class MessageSourceType : char {
    UNKNOWN = '?',
    SYSLOG_EVENT = '2',             // From remote syslog, forwarded by logcollector or direct
    AGENT_EVENT = '4',              // Standard Wazuh agent log (non-JSON or JSON)
    LOCALFILE_MQ_EVENT = '1',       // Matches existing LOCALFILE_MQ
};

// Structure to hold the output of the message cleaner
struct CleanedMessageData {
    std::string raw_full_message;      
    std::string agent_id;              
    std::string agent_name;            
    std::string agent_ip;              
    std::string location;              
    MessageSourceType source_type;     
    std::string actual_log_payload;    
    
    std::optional<long> extracted_timestamp; 
    std::string extracted_hostname;
    std::string extracted_program_name;

    bool parsing_error;                

    CleanedMessageData() : 
        source_type(MessageSourceType::UNKNOWN), 
        extracted_timestamp(std::nullopt),
        parsing_error(false) {}
};

using MessageDispatcher = std::function<void(CleanedMessageData&&)>;

class WazuhDefaultQueueReader
{
public:
    WazuhDefaultQueueReader(std::string queue_path, MessageDispatcher dispatcher);
    ~WazuhDefaultQueueReader();

    bool initialize();
    bool start();
    void stop();

private:
    void run_read_loop();

    std::string m_queue_path;
    int m_queue_fd;
    MessageDispatcher m_dispatcher;
    std::thread m_reader_thread;
    std::atomic<bool> m_is_running;
};

} // namespace wazuh::engine::input_adapters

#endif // ENGINE_WAZUH_QUEUE_READER_HPP
