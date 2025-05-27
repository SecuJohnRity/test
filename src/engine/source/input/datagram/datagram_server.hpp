#ifndef _INPUT_DATAGRAM_SERVER_HPP
#define _INPUT_DATAGRAM_SERVER_HPP

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include <common/protocol/datagramParser.hpp> // For ProtocolHandler
#include <router/iapi.hpp> // For router::IRouterAPI (orchestrator)
#include <base/logging.hpp>

namespace engine::input
{

class DatagramServer
{
public:
    DatagramServer(
        std::shared_ptr<router::IRouterAPI> orchestrator,
        common::protocol::ProtocolHandler parser,
        const std::string& host,
        int port);
    ~DatagramServer();

    DatagramServer(const DatagramServer&) = delete;
    DatagramServer& operator=(const DatagramServer&) = delete;

    /**
     * @brief Starts the datagram server.
     * @return True if started successfully, false otherwise.
     */
    bool start();

    /**
     * @brief Stops the datagram server.
     */
    void stop();

private:
    void listen(); // The function for the listening thread

    std::shared_ptr<router::IRouterAPI> m_orchestrator;
    common::protocol::ProtocolHandler m_parser;
    std::string m_host;
    int m_port;
    int m_socket_fd = -1;

    std::atomic<bool> m_running {false};
    std::thread m_listener_thread;
};

} // namespace engine::input

#endif // _INPUT_DATAGRAM_SERVER_HPP
