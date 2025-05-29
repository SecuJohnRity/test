#include <chrono>
#include <functional>
#include <vector> // Required for processDatagramPacket

#include <base/logging.hpp>

#include "router.hpp"
#include <builder/ibuilder.hpp>
// No need to include datagram_socket.h here as it's already in router.hpp

namespace
{
/**
 * @brief Return the current time in seconds since epoch
 */
int64_t getStartTime()
{
    auto startTime = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(startTime.time_since_epoch()).count();
}
} // namespace
namespace router
{

// Constructor 1
Router::Router(const std::shared_ptr<EnvironmentBuilder>& envBuilder)
    : m_table()
    , m_mutex()
    , m_envBuilder(envBuilder)
// datagramSocket_ will be initialized after fetching config
{
    // TODO: The Router needs access to the global Conf object to get these values.
    // This should be passed into the Router's constructor or retrieved from a central point.
    // For now, using default values as defined in conf.cpp.
    bool datagram_enabled = false;             // Default from conf.cpp: key::DATAGRAM_ENABLED
    int datagram_port = 514;                   // Default from conf.cpp: key::DATAGRAM_PORT
    std::string datagram_ip_address = "0.0.0.0"; // Default from conf.cpp: key::DATAGRAM_IP_ADDRESS
    std::string datagram_overflow_strategy = "discard"; // Default from conf.cpp: key::DATAGRAM_OVERFLOW_STRATEGY
    int datagram_buffer_size = 1048576;        // Default from conf.cpp: key::DATAGRAM_BUFFER_SIZE

    // Example of how it should be (assuming 'conf' is a std::shared_ptr<conf::Conf>):
    // datagram_enabled = conf->get<bool>(conf::key::DATAGRAM_ENABLED);
    // datagram_port = conf->get<int>(conf::key::DATAGRAM_PORT);
    // datagram_ip_address = conf->get<std::string>(conf::key::DATAGRAM_IP_ADDRESS);
    // datagram_overflow_strategy = conf->get<std::string>(conf::key::DATAGRAM_OVERFLOW_STRATEGY);
    // datagram_buffer_size = conf->get<int>(conf::key::DATAGRAM_BUFFER_SIZE);

    datagramSocket_ = std::make_unique<DatagramSocket>(
        datagram_enabled,
        datagram_port,
        datagram_ip_address,
        datagram_overflow_strategy,
        datagram_buffer_size);

    if (datagram_enabled) {
        // TODO: Start a dedicated thread to listen on datagramSocket_ and call
        // processDatagramPacket or enqueue messages.
        // Example: datagramSocket_->bind(); // Call bind if it's not done in DatagramSocket constructor
        LOG_INFO("Datagram socket configured and initialized in Router.");
    } else {
        LOG_INFO("Datagram socket is disabled via configuration in Router.");
    }
}

// Constructor 2
Router::Router(const std::weak_ptr<builder::IBuilder>& builder, std::shared_ptr<bk::IControllerMaker> controllerMaker)
    : m_table()
    , m_mutex()
    , m_envBuilder(std::make_shared<EnvironmentBuilder>(builder, controllerMaker))
// datagramSocket_ will be initialized after fetching config
{
    // TODO: The Router needs access to the global Conf object to get these values.
    // This should be passed into the Router's constructor or retrieved from a central point.
    // For now, using default values as defined in conf.cpp.
    bool datagram_enabled = false;             // Default from conf.cpp: key::DATAGRAM_ENABLED
    int datagram_port = 514;                   // Default from conf.cpp: key::DATAGRAM_PORT
    std::string datagram_ip_address = "0.0.0.0"; // Default from conf.cpp: key::DATAGRAM_IP_ADDRESS
    std::string datagram_overflow_strategy = "discard"; // Default from conf.cpp: key::DATAGRAM_OVERFLOW_STRATEGY
    int datagram_buffer_size = 1048576;        // Default from conf.cpp: key::DATAGRAM_BUFFER_SIZE

    // Example of how it should be (assuming 'conf' is a std::shared_ptr<conf::Conf>):
    // datagram_enabled = conf->get<bool>(conf::key::DATAGRAM_ENABLED);
    // datagram_port = conf->get<int>(conf::key::DATAGRAM_PORT);
    // datagram_ip_address = conf->get<std::string>(conf::key::DATAGRAM_IP_ADDRESS);
    // datagram_overflow_strategy = conf->get<std::string>(conf::key::DATAGRAM_OVERFLOW_STRATEGY);
    // datagram_buffer_size = conf->get<int>(conf::key::DATAGRAM_BUFFER_SIZE);

    datagramSocket_ = std::make_unique<DatagramSocket>(
        datagram_enabled,
        datagram_port,
        datagram_ip_address,
        datagram_overflow_strategy,
        datagram_buffer_size);

    if (datagram_enabled) {
        // TODO: Start a dedicated thread to listen on datagramSocket_ and call
        // processDatagramPacket or enqueue messages.
        // Example: datagramSocket_->bind(); // Call bind if it's not done in DatagramSocket constructor
        LOG_INFO("Datagram socket configured and initialized in Router.");
    } else {
        LOG_INFO("Datagram socket is disabled via configuration in Router.");
    }
}

base::OptError Router::addEntry(const prod::EntryPost& entryPost, bool ignoreFail)
{
    // Create the environment
    auto entry = RuntimeEntry(entryPost);
    try
    {
        auto uniqueEnv = m_envBuilder->create(entry.policy(), entry.filter());
        entry.hash(uniqueEnv->hash());
        entry.environment() = std::move(uniqueEnv);
    }
    catch (const std::exception& e)
    {
        if (!ignoreFail)
        {
            return base::Error {fmt::format("Failed to create the route: {}", e.what())};
        }
        entry.environment() = nullptr;
        entry.hash("");
        entry.lastUpdate(0);
    }
    entry.status(env::State::DISABLED); // It is disabled until all routes are ready

    // Add the entry to the table
    {
        std::unique_lock<std::shared_mutex> lock {m_mutex};
        if (m_table.nameExists(entryPost.name()))
        {
            return base::Error {"The name of the route is already in use"};
        }

        if (m_table.priorityExists(entryPost.priority()))
        {
            return base::Error {"The priority of the route  is already in use"};
        }
        m_table.insert(entryPost.name(), entryPost.priority(), std::move(entry));
    }

    return std::nullopt;
    ;
}

base::OptError Router::removeEntry(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }
    m_table.erase(name);
    return std::nullopt;
}

base::OptError Router::rebuildEntry(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }
    auto& entry = m_table.get(name);
    try
    {
        auto uniqueEnv = m_envBuilder->create(entry.policy(), entry.filter());
        entry.environment() = std::move(uniqueEnv);
        entry.lastUpdate(getStartTime());
        entry.hash(entry.environment()->hash());
        // Mantaing the status of the environment
    }
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Failed to reload the route: {}", e.what())};
    }

    return std::nullopt;
}

base::OptError Router::enableEntry(const std::string& name)
{
    std::unique_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }
    auto& entry = m_table.get(name);
    if (entry.environment() == nullptr)
    {
        return base::Error {"The route is not buided"};
    }
    entry.status(env::State::ENABLED);
    entry.lastUpdate(getStartTime());
    return {};
}

base::OptError Router::changePriority(const std::string& name, size_t priority)
{

    if (priority == 0)
    {
        return base::Error {"Priority of the route cannot be 0"};
    }

    if (priority > prod::Entry::maxPriority())
    {
        return base::Error {"Priority of the route cannot be greater than "
                            + std::to_string(prod::Entry::maxPriority())};
    }

    std::unique_lock lock {m_mutex};

    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }

    if (!m_table.setPriority(name, priority))
    {
        return base::Error {"Failed to change the priority, it is already in use"};
    }
    // Sync the priority
    m_table.get(name).priority(priority);

    return {};
}

std::list<prod::Entry> Router::getEntries() const
{
    std::shared_lock lock {m_mutex};
    std::list<prod::Entry> entries;

    for (const auto& entry : m_table)
    {
        entries.push_back(entry);
    }
    return entries;
}

base::RespOrError<prod::Entry> Router::getEntry(const std::string& name) const
{
    std::shared_lock lock {m_mutex};
    if (!m_table.nameExists(name))
    {
        return base::Error {"The route not exist"};
    }
    return m_table.get(name);
}

void Router::ingest(base::Event&& event)
{
    std::shared_lock lock {m_mutex};

    for (const auto& entry : m_table)
    {
        if (entry.status() == env::State::ENABLED && entry.environment()->isAccepted(event))
        {
            entry.environment()->ingest(std::move(event));
            event = nullptr;
            break;
        }
    }

    if (event)
    {
        LOG_WARNING("Event not processed: {}", event->str());
    }
}

void Router::processDatagramPacket(const std::vector<char>& packet_data)
{
    // Placeholder implementation
    LOG_INFO("Router received a datagram packet of size: {}. Processing not yet implemented.", packet_data.size());

    // TODO: Implement actual parsing of the packet_data (e.g., using LegacyMessageParser)
    // TODO: Convert the raw data into an internal message format (e.g., base::Event or a new specific type)
    // TODO: Potentially use a ConcurrentQueue to pass this data to the router's main processing logic
    //       to avoid complex locking or direct processing in the receiver thread.
    // Example:
    // LegacyMessageParser parser;
    // if (parser.parseMessage(packet_data.data(), packet_data.size())) {
    //     // Create a base::Event or similar
    //     // base::Event event = ...;
    //     // this->ingest(std::move(event)); // or enqueue it
    // } else {
    //     LOG_WARNING("Failed to parse legacy datagram message.");
    // }
}

} // namespace router
