#include "input_adapters/wazuh_queue_reader.hpp"
#include "input_adapters/wazuh_message_cleaner.hpp" // To call the cleaner

#include <base/logging.hpp> // Assuming engine's logging
#include <sys/select.h>     // For select()
#include <unistd.h>         // For sleep() 
#include <cerrno>           // For errno
#include <cstring>          // For strerror
#include <iostream>         // Fallback for logging if needed (should not be primary)
#include <chrono>           // For std::chrono::seconds

// Wazuh C library includes
extern "C" {
    #include "shared/defs.h"      // For OS_MAXSTR, DEFAULTQUEUE, etc.
    #include "shared/mq_op.h"     // For StartMQ
    #include "os_net/os_net.h"    // For OS_RecvUnix, OS_CloseUnix
}

// Ensure DEFAULTQUEUE is available; it's usually in shared/defs.h
#ifndef DEFAULTQUEUE
#define DEFAULTQUEUE "/queue/sockets/queue" 
#endif

namespace wazuh::engine::input_adapters
{

WazuhDefaultQueueReader::WazuhDefaultQueueReader(std::string queue_path, MessageDispatcher dispatcher)
    : m_queue_path(std::move(queue_path)),
      m_dispatcher(std::move(dispatcher)),
      m_queue_fd(-1),
      m_is_running(false)
{
    if (this->m_queue_path.empty()) {
        this->m_queue_path = DEFAULTQUEUE; // Use Wazuh's default queue path
    }
    LOG_INFO("WazuhDefaultQueueReader: Initialized for queue path '{}'.", this->m_queue_path);
}

WazuhDefaultQueueReader::~WazuhDefaultQueueReader()
{
    if (m_is_running.load(std::memory_order_acquire)) {
        stop();
    }
}

// Initialize uses m_queue_path set in constructor
bool WazuhDefaultQueueReader::initialize()
{
    LOG_INFO("WazuhDefaultQueueReader: Initializing MQ connection to '{}'.", m_queue_path);
    m_queue_fd = StartMQ(m_queue_path.c_str(), READ, 5); // 5 attempts

    if (m_queue_fd < 0) {
        LOG_ERROR("WazuhDefaultQueueReader: Failed to open Wazuh queue '{}': {}.", m_queue_path, strerror(errno));
        return false;
    }
    LOG_INFO("WazuhDefaultQueueReader: Successfully connected to Wazuh queue '{}' (fd: {}).", m_queue_path, m_queue_fd);
    return true;
}

bool WazuhDefaultQueueReader::start()
{
    if (m_queue_fd < 0) {
        LOG_ERROR("WazuhDefaultQueueReader: Cannot start. Queue not initialized for path '{}'.", m_queue_path);
        return false;
    }
    bool expected_is_running = false;
    if (!m_is_running.compare_exchange_strong(expected_is_running, true, std::memory_order_release, std::memory_order_acquire)) {
        LOG_WARN("WazuhDefaultQueueReader: Already running for queue '{}'.", m_queue_path);
        return true; 
    }
    
    try {
        m_reader_thread = std::thread(&WazuhDefaultQueueReader::run_read_loop, this);
    } catch (const std::exception& e) {
        LOG_ERROR("WazuhDefaultQueueReader: Failed to start reader thread for queue '{}': {}", m_queue_path, e.what());
        m_is_running.store(false, std::memory_order_release);
        return false;
    }
    LOG_INFO("WazuhDefaultQueueReader: Reader thread started for queue '{}'.", m_queue_path);
    return true;
}

void WazuhDefaultQueueReader::stop()
{
    LOG_INFO("WazuhDefaultQueueReader: Stopping reader for queue '{}'.", m_queue_path);
    m_is_running.store(false, std::memory_order_release);
    if (m_reader_thread.joinable()) {
        m_reader_thread.join();
    }
    if (m_queue_fd >= 0) {
        OS_CloseUnix(m_queue_fd); 
        m_queue_fd = -1;
        LOG_INFO("WazuhDefaultQueueReader: Closed Wazuh queue '{}'.", m_queue_path);
    }
}

void WazuhDefaultQueueReader::run_read_loop()
{
    char buffer[OS_MAXSTR + 1]; 
    LOG_INFO("WazuhDefaultQueueReader: Read loop started for queue: {}", m_queue_path);

    while (m_is_running.load(std::memory_order_acquire)) {
        if (m_queue_fd < 0) { 
            LOG_WARN("WazuhDefaultQueueReader: Queue FD is invalid for '{}', attempting to re-initialize.", m_queue_path);
            if (!initialize()) { // Attempt to re-initialize using member m_queue_path
                LOG_ERROR("WazuhDefaultQueueReader: Failed to re-initialize queue {}. Loop will pause before retrying or stopping.", m_queue_path);
                std::this_thread::sleep_for(std::chrono::seconds(5)); // Prevent rapid spin on persistent error
                continue; 
            }
        }

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(m_queue_fd, &read_fds);
        struct timeval tv;
        tv.tv_sec = 1; 
        tv.tv_usec = 0;

        int activity = select(m_queue_fd + 1, &read_fds, nullptr, nullptr, &tv);

        if (!m_is_running.load(std::memory_order_acquire)) { 
            break;
        }

        if (activity < 0) { 
            if (errno == EINTR) {
                LOG_DEBUG("WazuhDefaultQueueReader: select() interrupted by signal on queue {}. Continuing.", m_queue_path);
                continue; 
            }
            LOG_ERROR("WazuhDefaultQueueReader: select() error on queue {}: {} (errno {}). Closing FD.", m_queue_path, strerror(errno), errno);
            OS_CloseUnix(m_queue_fd); 
            m_queue_fd = -1;          
            std::this_thread::sleep_for(std::chrono::seconds(1)); 
            continue;
        }

        if (FD_ISSET(m_queue_fd, &read_fds)) {
            int received_len = OS_RecvUnix(m_queue_fd, buffer, OS_MAXSTR); 
            if (received_len > 0) {
                buffer[received_len] = '\0'; 
                CleanedMessageData cleaned_data = WazuhMessageCleaner::cleanMessage(buffer);
                if (m_dispatcher) {
                    m_dispatcher(std::move(cleaned_data));
                }
            } else if (received_len == 0) { 
                LOG_WARN("WazuhDefaultQueueReader: Received 0 bytes (EOF) from queue {} (writer closed or other issue). Closing FD.", m_queue_path);
                OS_CloseUnix(m_queue_fd);
                m_queue_fd = -1; 
                std::this_thread::sleep_for(std::chrono::seconds(1)); 
            } else { // received_len < 0
                if (errno != EAGAIN && errno != EWOULDBLOCK) { 
                    LOG_ERROR("WazuhDefaultQueueReader: OS_RecvUnix error on queue {}: {} (errno {}). Closing FD.", m_queue_path, strerror(errno), errno);
                    OS_CloseUnix(m_queue_fd);
                    m_queue_fd = -1; 
                    std::this_thread::sleep_for(std::chrono::seconds(1)); 
                }
                // If EAGAIN or EWOULDBLOCK, just loop again after select timeout.
            }
        }
        // If select timed out (activity == 0), loop continues and checks m_is_running.
    }
    LOG_INFO("WazuhDefaultQueueReader: Read loop stopped for queue: {}", m_queue_path);
}

} // namespace wazuh::engine::input_adapters
