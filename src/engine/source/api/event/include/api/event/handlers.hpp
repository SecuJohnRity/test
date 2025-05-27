#ifndef _API_EVENT_HANDLERS_HPP
#define _API_EVENT_HANDLERS_HPP

#include <queue>

#include <api/adapter/adapter.hpp>
#include <archiver/iarchiver.hpp>
#include <base/baseTypes.hpp>
#include <router/iapi.hpp>

namespace api::event::handlers
{
// Corrected typo from ProtolHandler to ProtocolHandler
using ProtocolHandler = std::function<std::queue<base::Event>(std::string&&)>;

adapter::RouteHandler pushEvent(const std::shared_ptr<::router::IRouterAPI>& orchestrator,
                                ProtocolHandler protocolHandler, // Corrected type
                                const std::shared_ptr<::archiver::IArchiver>& archiver);

} // namespace api::event::handlers

#endif // _API_EVENT_HANDLERS_HPP
