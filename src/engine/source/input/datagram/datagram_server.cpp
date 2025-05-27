#include "datagram_server.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>    // For close()
#include <cstring>     // For strerror, memset
#include <vector>
#include <chrono>      // For std::chrono::milliseconds

// Default buffer size for incoming datagrams
constexpr size_t DEFAULT_BUFFER_SIZE = 4096; // Adjust as needed

namespace engine::input
{

DatagramServer::DatagramServer(
    std::shared_ptr<router::IRouterAPI> orchestrator,
    common::protocol::ProtocolHandler parser,
    const std::string& host,
    int port)
    : m_orchestrator(orchestrator),
      m_parser(parser),
      m_host(host),
      m_port(port)
{
    if (!m_orchestrator)
    {
        throw std::runtime_error("Orchestrator cannot be null for DatagramServer");
    }
    if (!m_parser)
    {
        throw std::runtime_error("Parser cannot be null for DatagramServer");
    }
}

DatagramServer::~DatagramServer()
{
    stop();
}

bool DatagramServer::start()
{
    if (m_running.load())
    {
        LOG_WARNING("DatagramServer already running on port {}", m_port);
        return true;
    }

    m_socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (m_socket_fd < 0)
    {
        LOG_ERROR("Failed to create datagram socket for port {}: {}", m_port, strerror(errno));
        return false;
    }

    // Set SO_REUSEADDR to allow reuse of local addresses
    int reuse = 1;
    if (setsockopt(m_socket_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        LOG_WARNING("Failed to set SO_REUSEADDR on socket for port {}: {}", m_port, strerror(errno));
        // Not fatal, but log it
    }


    struct sockaddr_in server_address {};
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(m_port);

    if (m_host == "0.0.0.0" || m_host == "::") { // Accept common "any interface" addresses
        server_address.sin_addr.s_addr = INADDR_ANY;
    } else if (inet_pton(AF_INET, m_host.c_str(), &server_address.sin_addr) <= 0) {
        LOG_ERROR("Invalid address/Address not supported for IPv4: {}. Error: {}", m_host, strerror(errno));
        close(m_socket_fd);
        m_socket_fd = -1;
        return false;
    }


    if (bind(m_socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0)
    {
        LOG_ERROR("Failed to bind datagram socket to {}:{}: {}", m_host, m_port, strerror(errno));
        close(m_socket_fd);
        m_socket_fd = -1;
        return false;
    }

    m_running = true;
    m_listener_thread = std::thread(&DatagramServer::listen, this);
    LOG_INFO("DatagramServer started on {}:{}", m_host, m_port);
    return true;
}

void DatagramServer::stop()
{
    bool expected = true;
    if (m_running.compare_exchange_strong(expected, false)) // Ensure stop() logic runs once
    {
        LOG_INFO("Stopping DatagramServer on {}:{}", m_host, m_port);
        if (m_socket_fd >= 0)
        {
            // Closing the socket will cause recvfrom to return an error,
            // which will help the listener thread to exit its loop.
            // Shutdown can also be used to interrupt blocking calls.
            shutdown(m_socket_fd, SHUT_RDWR); // Interrupt recvfrom
            close(m_socket_fd);
            m_socket_fd = -1; // Mark as closed
            LOG_INFO("DatagramServer socket on {}:{} closed.", m_host, m_port);
        }

        if (m_listener_thread.joinable())
        {
            m_listener_thread.join();
            LOG_INFO("DatagramServer listener thread on {}:{} joined.", m_host, m_port);
        }
    }
}

void DatagramServer::listen()
{
    std::vector<char> buffer(DEFAULT_BUFFER_SIZE);
    struct sockaddr_in client_address {}; // For IPv4
    socklen_t client_len = sizeof(client_address);

    LOG_INFO("DatagramServer listening on {}:{}", m_host, m_port);

    while (m_running.load())
    {
        ssize_t bytes_received = recvfrom(
            m_socket_fd,
            buffer.data(),
            buffer.size() -1, // Leave space for potential null terminator if needed by some parsers
            0, // flags
            (struct sockaddr*)&client_address,
            &client_len);

        if (!m_running.load()) {
             // Server is stopping, recvfrom might fail due to socket closure or shutdown.
            LOG_DEBUG("Server not running or recvfrom interrupted on port {}. Exiting listen loop.", m_port);
            break;
        }

        if (bytes_received < 0)
        {
            if (errno == EINTR) { // Interrupted system call, possibly by shutdown()
                 LOG_DEBUG("recvfrom interrupted on port {}.", m_port);
                 continue; // Check m_running again
            }
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                // Should not happen with blocking sockets unless a timeout is set.
                // If it does, just continue.
                continue;
            }
            // Other errors (e.g., EBADF if socket closed by stop())
            LOG_ERROR("Datagram recvfrom error on port {}: {} (errno: {})", m_port, strerror(errno), errno);
            // If the socket was closed by stop(), m_running should be false soon.
            // Otherwise, if it's a persistent error, we might spin.
            // A small delay can prevent tight loops on certain errors.
            if(m_running.load()) { // Only sleep if we are supposed to be running
                 std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            continue;
        }

        if (bytes_received == 0)
        {
            LOG_DEBUG("Received 0-byte datagram on port {}. Ignoring.", m_port);
            continue;
        }
        
        // Construct string with received data length
        std::string datagram_str(buffer.data(), static_cast<size_t>(bytes_received));

        LOG_TRACE("Received datagram on port {}: {}", m_port, datagram_str);

        try
        {
            // The parser function is expected to handle exceptions internally or be robust.
            std::queue<base::Event> events = m_parser(std::move(datagram_str));
            while (!events.empty())
            {
                if (m_orchestrator) 
                {
                    LOG_TRACE("Posting parsed datagram event to orchestrator from port {}", m_port);
                    m_orchestrator->postEvent(std::move(events.front()));
                }
                events.pop();
            }
        }
        catch (const std::exception& e)
        {
            // Log and continue, so one bad datagram doesn't stop the server.
            LOG_ERROR("Exception during datagram parsing/processing on port {}: {}. Datagram (first 256 chars): '{}'", 
                      m_port, e.what(), datagram_str.substr(0, 256));
        }
        catch (...)
        {
            LOG_ERROR("Unknown exception during datagram parsing/processing on port {}. Datagram (first 256 chars): '{}'", 
                      m_port, datagram_str.substr(0, 256));
        }
    }
    LOG_INFO("DatagramServer listener thread on {}:{} stopped.", m_host, m_port);
}

} // namespace engine::input
