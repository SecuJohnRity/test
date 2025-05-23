#include <atomic>
#include <csignal>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <api/archiver/handlers.hpp>
#include <api/catalog/catalog.hpp>
#include <api/event/ndJsonParser.hpp>
#include <api/handlers.hpp>
#include <api/policy/policy.hpp>
#include <archiver/archiver.hpp>
#include <base/logging.hpp>
#include <base/utils/singletonLocator.hpp>
#include <base/utils/singletonLocatorStrategies.hpp>
#include <bk/rx/controller.hpp>
#include <builder/allowedFields.hpp>
#include <builder/builder.hpp>
#include <conf/conf.hpp>
#include <conf/keys.hpp>
#include <defs/defs.hpp>
#include <eMessages/eMessage.h>
#include <geo/downloader.hpp>
#include <geo/manager.hpp>
#include <httpsrv/server.hpp>
#include <indexerConnector/indexerConnector.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logpar/logpar.hpp>
#include <logpar/registerParsers.hpp>
#include <metrics/manager.hpp>
#include <queue/concurrentQueue.hpp>
#include <rbac/rbac.hpp>
#include <router/orchestrator.hpp>
#include <schemf/schema.hpp>
#include <store/drivers/fileDriver.hpp>
#include <store/store.hpp>
#include <vdscanner/scanOrchestrator.hpp>

#ifdef ENGINE_FORWARDING_POC
#include <actions/ar_action.hpp> // For PoC Active Response
#endif

#include "base/utils/getExceptionStack.hpp"
#include "stackExecutor.hpp"

namespace
{
struct QueueTraits : public moodycamel::ConcurrentQueueDefaultTraits
{
    static constexpr size_t BLOCK_SIZE = 2048;
    static constexpr size_t IMPLICIT_INITIAL_INDEX_SIZE = 8192;
};
} // namespace

std::shared_ptr<httpsrv::Server> g_engineServer {};

void sigintHandler(const int signum)
{
    if (g_engineServer)
    {
        g_engineServer.reset();
    }
}

int main(int argc, char* argv[])
{
    // exit handler
    cmd::details::StackExecutor exitHandler {};

    // Initialize logging
    {
        logging::LoggingConfig logConfig;
        logConfig.level = logging::Level::Info; // Default log level
        exitHandler.add([]() { logging::stop(); });
        logging::start(logConfig);
        LOG_INFO("Logging initialized.");
    }

    // Load the configuration

    auto confManager = conf::Conf(std::make_shared<conf::ApiLoader>());
    try
    {
        confManager.load();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error loading configuration: {}", e.what());
        exit(EXIT_FAILURE);
    }

    // Set signal [SIGINT]: Crt+C handler
    {
        // Set the signal handler for SIGINT
        struct sigaction sigIntHandler = {};
        sigIntHandler.sa_handler = sigintHandler;
        sigemptyset(&sigIntHandler.sa_mask);
        sigIntHandler.sa_flags = 0;
        sigaction(SIGINT, &sigIntHandler, nullptr);
    }
    // Set signal [EPIPE]: Broken pipe handler
    {
        // Set the signal handler for EPIPE (uvw/libuv/libev)
        // https://github.com/skypjack/uvw/issues/291
        struct sigaction sigPipeHandler = {};
        sigPipeHandler.sa_handler = SIG_IGN;
        sigemptyset(&sigPipeHandler.sa_mask);
        sigPipeHandler.sa_flags = 0;
        sigaction(SIGPIPE, &sigPipeHandler, nullptr);
    }

    // Init modules
    std::shared_ptr<store::Store> store;
    std::shared_ptr<builder::Builder> builder;
    std::shared_ptr<api::catalog::Catalog> catalog;
    std::shared_ptr<router::Orchestrator> orchestrator;
    std::shared_ptr<hlp::logpar::Logpar> logpar;
    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
    std::shared_ptr<geo::Manager> geoManager;
    std::shared_ptr<schemf::Schema> schema;
    std::shared_ptr<rbac::RBAC> rbac;
    std::shared_ptr<api::policy::IPolicy> policyManager;
    std::shared_ptr<vdscanner::ScanOrchestrator> vdScanner;
    std::shared_ptr<IIndexerConnector> iConnector;
    std::shared_ptr<httpsrv::Server> apiServer;
    std::shared_ptr<archiver::Archiver> archiver;

    try
    {
        // Set new log level if it is different from the default
        {
            const auto level = logging::strToLevel(confManager.get<std::string>(conf::key::LOGGING_LEVEL));
            const auto currentLevel = logging::getLevel();
            if (level != currentLevel)
            {
                logging::setLevel(level);
                LOG_DEBUG("Changed log level to '{}'", logging::levelToStr(level));
            }
        }

        // Metrics
        {
            SingletonLocator::registerManager<metrics::IManager,
                                              base::PtrSingleton<metrics::IManager, metrics::Manager>>();
            auto config = std::make_shared<metrics::Manager::ImplConfig>();
            config->logLevel = logging::Level::Err;
            config->exportInterval =
                std::chrono::milliseconds(confManager.get<int64_t>(conf::key::METRICS_EXPORT_INTERVAL));
            config->exportTimeout =
                std::chrono::milliseconds(confManager.get<int64_t>(conf::key::METRICS_EXPORT_TIMEOUT));

            // TODO Update index configuration when it is defined
            IndexerConnectorOptions icConfig {};
            icConfig.name = "metrics-index";
            icConfig.hosts = confManager.get<std::vector<std::string>>(conf::key::INDEXER_HOST);
            icConfig.username = confManager.get<std::string>(conf::key::INDEXER_USER);
            icConfig.password = confManager.get<std::string>(conf::key::INDEXER_PASSWORD);
            if (confManager.get<bool>(conf::key::INDEXER_SSL_USE_SSL))
            {
                icConfig.sslOptions.cacert = confManager.get<std::string>(conf::key::INDEXER_SSL_CA_BUNDLE);
                icConfig.sslOptions.cert = confManager.get<std::string>(conf::key::INDEXER_SSL_CERTIFICATE);
                icConfig.sslOptions.key = confManager.get<std::string>(conf::key::INDEXER_SSL_KEY);
            }

            icConfig.databasePath = confManager.get<std::string>(conf::key::INDEXER_DB_PATH);
            const auto to = confManager.get<int>(conf::key::INDEXER_TIMEOUT);
            if (to < 0)
            {
                throw std::runtime_error("Invalid indexer timeout value.");
            }
            icConfig.timeout = to;
            const auto wt = confManager.get<int>(conf::key::INDEXER_THREADS);
            if (wt < 0)
            {
                throw std::runtime_error("Invalid indexer threads value.");
            }
            icConfig.workingThreads = wt;

            config->indexerConnectorFactory = [icConfig]() -> std::shared_ptr<IIndexerConnector>
            {
                return std::make_shared<IndexerConnector>(icConfig);
            };

            SingletonLocator::instance<metrics::IManager>().configure(config);

            LOG_INFO("Metrics initialized.");

            if (confManager.get<bool>(conf::key::METRICS_ENABLED))
            {
                SingletonLocator::instance<metrics::IManager>().enable();
                LOG_INFO("Metrics enabled.");
            }
            else
            {
                SingletonLocator::instance<metrics::IManager>().disable();
                LOG_INFO("Metrics disabled.");
            }

            exitHandler.add(
                []()
                {
                    SingletonLocator::instance<metrics::IManager>().disable();
                    SingletonLocator::clear();
                });
        }

        // Store
        {
            auto fileStorage = confManager.get<std::string>(conf::key::STORE_PATH);
            auto fileDriver = std::make_shared<store::drivers::FileDriver>(fileStorage);
            store = std::make_shared<store::Store>(fileDriver);
            LOG_INFO("Store initialized.");
        }

        // RBAC
        {
            rbac = std::make_shared<rbac::RBAC>(store);
            LOG_INFO("RBAC initialized.");
        }

        // KVDB
        {
            kvdbManager::KVDBManagerOptions kvdbOptions {confManager.get<std::string>(conf::key::KVDB_PATH), "kvdb"};
            kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbOptions);
            kvdbManager->initialize();
            LOG_INFO("KVDB initialized.");
            exitHandler.add(
                [kvdbManager, functionName = logging::getLambdaName(__FUNCTION__, "exitHandler")]()
                {
                    kvdbManager->finalize();
                    LOG_INFO_L(functionName.c_str(), "KVDB terminated.");
                });
        }

        // GEO
        {
            // TODO: This is a optional right now, but it be mandatory in the future
            auto geoDownloader = std::make_shared<geo::Downloader>();
            geoManager = std::make_shared<geo::Manager>(store, geoDownloader);
            LOG_INFO("Geo initialized.");
        }

        // Schema
        {
            schema = std::make_shared<schemf::Schema>();
            auto result = store->readInternalDoc("schema/engine-schema/0");
            if (std::holds_alternative<base::Error>(result))
            {
                LOG_WARNING("Error loading schema definition: {}", std::get<base::Error>(result).message);
                LOG_WARNING("Engine running without schema, consistency with indexer mappings is not guaranteed.");
            }
            else
            {
                auto schemaJson = std::get<json::Json>(result);
                schema->load(schemaJson);
            }
            LOG_INFO("Schema initialized.");
        }

        // HLP
        {
            hlp::initTZDB(confManager.get<std::string>(conf::key::TZDB_PATH),
                          confManager.get<bool>(conf::key::TZDB_AUTO_UPDATE));

            base::Name logparFieldOverrides({"schema", "wazuh-logpar-overrides", "0"});
            auto res = store->readInternalDoc(logparFieldOverrides);
            if (std::holds_alternative<base::Error>(res))
            {
                throw std::runtime_error(fmt::format("Could not retreive logpar field overrides [{}] needed by the "
                                                     "HLP module, error: {}",
                                                     logparFieldOverrides.fullName(),
                                                     base::getError(res).message));
            }
            logpar = std::make_shared<hlp::logpar::Logpar>(base::getResponse<store::Doc>(res), schema);
            hlp::registerParsers(logpar);
            LOG_INFO("HLP initialized.");
        }

        // Indexer Connector
        {
            IndexerConnectorOptions icConfig {};
            icConfig.name = confManager.get<std::string>(conf::key::INDEXER_INDEX);
            icConfig.hosts = confManager.get<std::vector<std::string>>(conf::key::INDEXER_HOST);
            icConfig.username = confManager.get<std::string>(conf::key::INDEXER_USER);
            icConfig.password = confManager.get<std::string>(conf::key::INDEXER_PASSWORD);
            if (confManager.get<bool>(conf::key::INDEXER_SSL_USE_SSL))
            {
                icConfig.sslOptions.cacert = confManager.get<std::string>(conf::key::INDEXER_SSL_CA_BUNDLE);
                icConfig.sslOptions.cert = confManager.get<std::string>(conf::key::INDEXER_SSL_CERTIFICATE);
                icConfig.sslOptions.key = confManager.get<std::string>(conf::key::INDEXER_SSL_KEY);
                icConfig.sslOptions.skipVerifyPeer = !confManager.get<bool>(conf::key::INDEXER_SSL_VERIFY_CERTS);
            }
            else
            {
                // If not use SSL, check if url start with https
                for (const auto& host : icConfig.hosts)
                {
                    if (base::utils::string::startsWith(host, "https://"))
                    {
                        throw std::runtime_error(fmt::format(
                            "The host '{}' for indexer connector is using HTTPS but the SSL options are not "
                            "enabled.",
                            host));
                    }
                }
            }

            icConfig.databasePath = confManager.get<std::string>(conf::key::INDEXER_DB_PATH);
            const auto to = confManager.get<int>(conf::key::INDEXER_TIMEOUT);
            if (to < 0)
            {
                throw std::runtime_error("Invalid indexer timeout value.");
            }
            icConfig.timeout = to;
            const auto wt = confManager.get<int>(conf::key::INDEXER_THREADS);
            if (wt < 0)
            {
                throw std::runtime_error("Invalid indexer threads value.");
            }
            icConfig.workingThreads = wt;

            iConnector = std::make_shared<IndexerConnector>(icConfig);
            LOG_INFO("Indexer Connector initialized.");
        }

        // Builder and registry
        {
            builder::BuilderDeps builderDeps;
            builderDeps.logparDebugLvl = 0;
            builderDeps.logpar = logpar;
            builderDeps.kvdbScopeName = "builder";
            builderDeps.kvdbManager = kvdbManager;
            builderDeps.geoManager = geoManager;
            builderDeps.iConnector = iConnector;
            auto defs = std::make_shared<defs::DefinitionsBuilder>();

            // Build allowed fields
            std::shared_ptr<builder::IAllowedFields> allowedFields;
            auto allowedFieldsDoc = store->readInternalDoc("schema/allowed-fields/0");
            if (std::holds_alternative<base::Error>(allowedFieldsDoc))
            {
                LOG_DEBUG("Could not load 'schema/allowed-fields/0' document, {}",
                          std::get<base::Error>(allowedFieldsDoc).message);
                LOG_WARNING("Allowed fields not found, assets will not have restrictions.");

                allowedFields = std::make_shared<builder::AllowedFields>();
            }
            else
            {
                allowedFields =
                    std::make_shared<builder::AllowedFields>(base::getResponse<store::Doc>(allowedFieldsDoc));
            }

            builder = std::make_shared<builder::Builder>(store, schema, defs, allowedFields, builderDeps);
            LOG_INFO("Builder initialized.");
        }

        // Catalog
        {
            api::catalog::Config catalogConfig {store, builder};

            catalog = std::make_shared<api::catalog::Catalog>(catalogConfig);
            LOG_INFO("Catalog initialized.");
        }

        // Policy manager
        {
            policyManager = std::make_shared<api::policy::Policy>(store, builder);
            LOG_INFO("Policy manager initialized.");
        }

        // Router
        {
            // External queues
            using QEventType = base::queue::ConcurrentQueue<base::Event, QueueTraits>;
            using QTestType = base::queue::ConcurrentQueue<router::test::QueueType>;

            std::shared_ptr<QEventType> eventQueue {};
            std::shared_ptr<QTestType> testQueue {};
            {
                // TODO queueFloodFile, queueFloodAttempts, queueFloodSleep -> Move to Queue.flood options
                eventQueue = std::make_shared<QEventType>(confManager.get<int>(conf::key::QUEUE_SIZE),
                                                          "routerEventQueue",
                                                          confManager.get<std::string>(conf::key::QUEUE_FLOOD_FILE),
                                                          confManager.get<int>(conf::key::QUEUE_FLOOD_ATTEMPS),
                                                          confManager.get<int>(conf::key::QUEUE_FLOOD_SLEEP),
                                                          confManager.get<bool>(conf::key::QUEUE_DROP_ON_FLOOD));
                LOG_DEBUG("Event queue created.");
            }

            {
                testQueue = std::make_shared<QTestType>(confManager.get<int>(conf::key::QUEUE_SIZE), "routerTestQueue");
                LOG_DEBUG("Test queue created.");
            }

            router::Orchestrator::Options config {.m_numThreads = confManager.get<int>(conf::key::ORCHESTRATOR_THREADS),
                                                  .m_wStore = store,
                                                  .m_builder = builder,
                                                  .m_controllerMaker = std::make_shared<bk::rx::ControllerMaker>(),
                                                  .m_prodQueue = eventQueue,
                                                  .m_testQueue = testQueue,
                                                  .m_testTimeout = confManager.get<int>(conf::key::SERVER_API_TIMEOUT)};

            orchestrator = std::make_shared<router::Orchestrator>(config);
            orchestrator->start();

            exitHandler.add([orchestrator]() { orchestrator->stop(); });
            LOG_INFO("Router initialized.");
        }

        // VD Scanner
        {
            vdScanner = std::make_shared<vdscanner::ScanOrchestrator>();
        }

        // Archiver
        {
            archiver = std::make_shared<archiver::Archiver>(confManager.get<std::string>(conf::key::ARCHIVER_PATH),
                                                            confManager.get<bool>(conf::key::ARCHIVER_ENABLED));
            LOG_INFO("Archiver initialized.");
        }

        // Create and configure the api endpints
        {
            apiServer = std::make_shared<httpsrv::Server>("API_SRV");

            // API
            exitHandler.add(
                [apiServer]()
                {
                    apiServer->stop();
                    eMessage::ShutdownEMessageLibrary();
                });

            // TODO Add Metrics API registration

            // Catalog
            api::catalog::handlers::registerHandlers(catalog, apiServer);
            LOG_DEBUG("Catalog API registered.");

            // Geo
            api::geo::handlers::registerHandlers(geoManager, apiServer);
            LOG_DEBUG("Geo API registered.");

            // KVDB
            api::kvdb::handlers::registerHandlers(kvdbManager, apiServer);
            LOG_DEBUG("KVDB API registered.");

            // Policy
            api::policy::handlers::registerHandlers(policyManager, apiServer);
            LOG_DEBUG("Policy API registered.");

            // Router
            api::router::handlers::registerHandlers(orchestrator, policyManager, apiServer);
            LOG_DEBUG("Router API registered.");

            // Tester
            api::tester::handlers::registerHandlers(orchestrator, store, policyManager, apiServer);
            LOG_DEBUG("Tester API registered.");

            // Add apidoc documentation.
            /**
             * @api {post} /vulnerability/scan Scan OS and packages for vulnerabilities
             * @apiName scan
             * @apiGroup vulnerability
             * @apiVersion 0.1.0
             *
             * @apiBody {String} type Type of scan to perform.
             * @apiBody {Object} agent Agent information.
             * @apiBody {String} agent.id ID of the agent.
             * @apiBody {Object[]} packages List of packages to scan.
             * @apiBody {String} packages.architecture Architecture of the package.
             * @apiBody {String} packages.checksum Checksum of the package.
             * @apiBody {String} packages.description Description of the package.
             * @apiBody {String} packages.format Format of the package (e.g., deb).
             * @apiBody {String} packages.groups Groups to which the package belongs.
             * @apiBody {String} packages.item_id Item ID of the package.
             * @apiBody {String} packages.multiarch Multiarch compatibility.
             * @apiBody {String} packages.name Name of the package.
             * @apiBody {String} packages.priority Priority of the package.
             * @apiBody {String} packages.scan_time Scan time of the package.
             * @apiBody {Number} packages.size Size of the package in MB.
             * @apiBody {String} packages.source Source of the package.
             * @apiBody {String} packages.vendor Vendor of the package.
             * @apiBody {String} packages.version Version of the package.
             * @apiBody {String[]} hotfixes List of hotfixes to scan.
             * @apiBody {Object} os OS information.
             * @apiBody {String} os.architecture OS architecture.
             * @apiBody {String} os.checksum OS checksum.
             * @apiBody {String} os.hostname Hostname of the OS.
             * @apiBody {String} os.codename Codename of the OS.
             * @apiBody {String} os.major_version Major version of the OS.
             * @apiBody {String} os.minor_version Minor version of the OS.
             * @apiBody {String} os.name Name of the OS.
             * @apiBody {String} os.patch Patch level of the OS.
             * @apiBody {String} os.platform Platform of the OS.
             * @apiBody {String} os.version Version name of the OS.
             * @apiBody {String} os.scan_time Scan time of the OS.
             * @apiBody {String} os.kernel_release Kernel release version.
             * @apiBody {String} os.kernel_name Kernel name.
             * @apiBody {String} os.kernel_version Kernel version.
             *
             * @apiSuccess {Object[]} vulnerabilities List of detected vulnerabilities.
             * @apiSuccess {String} vulnerabilities.assigner Assigner of the vulnerability.
             * @apiSuccess {String} vulnerabilities.category Category of the vulnerability.
             * @apiSuccess {String} vulnerabilities.classification Classification type (e.g., CVSS).
             * @apiSuccess {String} vulnerabilities.condition Condition that triggered the vulnerability detection.
             * @apiSuccess {Object} vulnerabilities.cvss CVSS score details.
             * @apiSuccess {Object} vulnerabilities.cvss.cvss3 CVSS v3.0 scoring details.
             * @apiSuccess {Object} vulnerabilities.cvss.cvss3.vector CVSS v3.0 vector details.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.attack_vector Attack vector.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.availability Availability impact.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.confidentiality_impact Confidentiality impact.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.integrity_impact Integrity impact.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.privileges_required Privileges required.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.scope Scope of the vulnerability.
             * @apiSuccess {String} vulnerabilities.cvss.cvss3.vector.user_interaction User interaction requirement.
             * @apiSuccess {String} vulnerabilities.cwe_reference CWE reference for the vulnerability.
             * @apiSuccess {String} vulnerabilities.description Description of the vulnerability.
             * @apiSuccess {String} vulnerabilities.detected_at Detection time in ISO format.
             * @apiSuccess {String} vulnerabilities.enumeration Enumeration type (e.g., CVE).
             * @apiSuccess {String} vulnerabilities.id ID of the vulnerability (e.g., CVE ID).
             * @apiSuccess {String} vulnerabilities.item_id Internal item ID related to the vulnerability.
             * @apiSuccess {String} vulnerabilities.published_at Published date of the vulnerability.
             * @apiSuccess {String} vulnerabilities.reference URL reference for more details about the vulnerability.
             * @apiSuccess {Object} vulnerabilities.score Vulnerability score details.
             * @apiSuccess {Number} vulnerabilities.score.base Base score of the vulnerability.
             * @apiSuccess {String} vulnerabilities.score.version CVSS version.
             * @apiSuccess {String} vulnerabilities.severity Severity level (e.g., High, Medium).
             * @apiSuccess {String} vulnerabilities.updated Last updated time of the vulnerability.
             *
             * @apiSuccessExample {json} Success-Response:
             *    HTTP/1.1 200 OK
             *   [
             *     {
             *       "assigner": "microsoft",
             *       "category": "Packages",
             *       "classification": "CVSS",
             *       "condition": "Package equal to 2016",
             *       "cvss": {
             *         "cvss3": {
             *           "vector": {
             *             "attack_vector": "",
             *             "availability": "HIGH",
             *             "confidentiality_impact": "HIGH",
             *             "integrity_impact": "HIGH",
             *             "privileges_required": "NONE",
             *             "scope": "UNCHANGED",
             *             "user_interaction": "REQUIRED"
             *           }
             *         }
             *       },
             *       "cwe_reference": "CWE-20",
             *       "description": "Microsoft Outlook Remote Code Execution Vulnerability",
             *       "detected_at": "2024-09-04T18:00:02.747Z",
             *       "enumeration": "CVE",
             *       "id": "CVE-2024-38021",
             *       "item_id": "eff251a49a142accf85b170526462e13d3265f03",
             *       "published_at": "2024-07-09T17:15:28Z",
             *       "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38021",
             *       "score": {
             *         "base": 8.8,
             *         "version": "3.1"
             *       },
             *       "severity": "High",
             *       "updated": "2024-07-11T16:49:16Z"
             *     },
             *     {
             *       "assigner": "microsoft",
             *       "category": "Packages",
             *       "classification": "CVSS",
             *       "condition": "Package equal to 2016",
             *       "cvss": {
             *         "cvss3": {
             *           "vector": {
             *             "attack_vector": "",
             *             "availability": "NONE",
             *             "confidentiality_impact": "HIGH",
             *             "integrity_impact": "NONE",
             *             "privileges_required": "NONE",
             *             "scope": "UNCHANGED",
             *             "user_interaction": "REQUIRED"
             *           }
             *         }
             *       },
             *       "cwe_reference": "CWE-200",
             *       "description": "Microsoft Outlook Spoofing Vulnerability",
             *       "detected_at": "2024-09-04T18:00:02.747Z",
             *       "enumeration": "CVE",
             *       "id": "CVE-2024-38020",
             *       "item_id": "eff251a49a142accf85b170526462e13d3265f03",
             *       "published_at": "2024-07-09T17:15:28Z",
             *       "reference": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38020",
             *       "score": {
             *         "base": 6.5,
             *         "version": "3.1"
             *       },
             *       "severity": "Medium",
             *       "updated": "2024-07-11T16:49:29Z"
             *     }
             *   ]
             *
             * @apiError {String} error Error message.
             * @apiError {Number} code Error code.
             *
             * @apiErrorExample {json} Error-Response:
             *   HTTP/1.1 503 Service Unavailable
             *  {
             *   "error": "Service Unavailable",
             *   "code": 503
             *  }
             */
            apiServer->addRoute(httpsrv::Method::POST,
                                "/vulnerability/scan",
                                [vdScanner](const auto& req, auto& res)
                                {
                                    vdScanner->processEvent(req.body, res.body);
                                    res.set_header("Content-Type", "application/json");
                                });
            LOG_DEBUG("VD API endpoint registered.");

            // Archiver
            api::archiver::handlers::registerHandlers(archiver, apiServer);
            LOG_DEBUG("Archiver API registered.");

            // Finally start the API server
            apiServer->start(confManager.get<std::string>(conf::key::SERVER_API_SOCKET));
        }

        // Server
        {
            g_engineServer = std::make_shared<httpsrv::Server>("EVENT_SRV");

#ifdef ENGINE_FORWARDING_POC
            auto pocNdjsonPushEventHandler = 
                [&orchestrator, &archiver, lambdaName = logging::getLambdaName(__FUNCTION__, "pocNdjsonPushEventHandler")]
                (const auto& req, auto& res) {
                LOG_TRACE_L(lambdaName.c_str(), fmt::format("PoC Handler: Received request body: {}", req.body));

                if (req.body.empty()) {
                    LOG_WARN_L(lambdaName.c_str(), "PoC Handler: Received empty request body.");
                    res.status = httplib::StatusCode::BadRequest_400;
                    res.set_content("{\"error\": \"Empty request body\", \"code\": 400}", "application/json");
                    return;
                }
                
                // Assuming each line in NDJSON is a separate event, but PoC sends one JSON object per request.
                // If multiple JSON objects could arrive in one body, req.body would need splitting by '\n'.
                // For this PoC, treat the entire body as a single JSON object.
                base::Event event;
                try {
                    event = std::make_shared<json::Json>(req.body.c_str());
                } catch (const std::exception& e) {
                    LOG_ERROR_L(lambdaName.c_str(), "PoC Handler: Failed to parse JSON: {}. Body: {}", e.what(), req.body);
                    res.status = httplib::StatusCode::BadRequest_400;
                    res.set_content(fmt::format("{{\"error\": \"Malformed JSON: {}\", \"code\": 400}}", e.what()), "application/json");
                    return;
                }

                if (event->isNull()) { 
                     LOG_ERROR_L(lambdaName.c_str(), "PoC Handler: Parsed JSON is null. Body: {}", req.body);
                     res.status = httplib::StatusCode::BadRequest_400;
                     res.set_content("{\"error\": \"Malformed JSON resulted in null object\", \"code\": 400}", "application/json");
                     return;
                }

                // Validate required fields for the PoC
                if (!event->exists("/original_log") || !event->isString("/original_log")) {
                    LOG_ERROR_L(lambdaName.c_str(), "PoC Handler: NDJSON missing 'original_log' string field: {}", req.body);
                    res.status = httplib::StatusCode::BadRequest_400;
                    res.set_content("{\"error\": \"NDJSON missing original_log string field\", \"code\": 400}", "application/json");
                    return;
                }
                if (!event->exists("/agent_id") || !event->isString("/agent_id")) {
                    LOG_WARN_L(lambdaName.c_str(), "PoC Handler: NDJSON missing 'agent_id' string field in body: {}", req.body);
                    // Proceeding without agent_id for PoC, but real scenario might require it
                }

                // Archive the raw received body
                if (archiver) { 
                    archiver->archive(std::string(req.body)); 
                }

                // POC Rule Check and Alerting
                std::string original_log_str = event->getString("/original_log").value_or("");
                if (original_log_str.find("POC_REMOTED_MATCH_THIS") != std::string::npos) {
                    LOG_INFO_L(lambdaName.c_str(), "PoC Rule: Match found for 'POC_REMOTED_MATCH_THIS'");
                    json::Json alert_output = json::Json::object(); // Create an object: {}
                    alert_output.setInt(100001, "/poc_alert/rule_id");
                    alert_output.setString("PoC Rule: Matched 'POC_REMOTED_MATCH_THIS' in original_log", "/poc_alert/description");
                    alert_output.setString(event->getString("/agent_id").value_or("UNKNOWN"), "/poc_alert/agent_id");
                    
                    // Include the original event that triggered the alert
                    // Ensure event is treated as const or copied if modified by set
                    // Since base::Event is std::shared_ptr<json::Json>, *event gives the json::Json object
                    alert_output.set("/poc_alert/original_event_data", *event);

                    std::string alert_string = alert_output.str(); // Serialize to string (compact)
                                                                    // Use prettyStr() for formatted output if preferred for debugging
                    
                    if (archiver) {
                        archiver->archive(std::move(alert_string)); // Pass by rvalue reference
                        LOG_INFO_L(lambdaName.c_str(), "PoC Alert: Alert for rule 100001 sent to archiver.");
                    }

                    // Trigger PoC Active Response
                    LOG_INFO_L(lambdaName.c_str(), "PoC Rule: Attempting to trigger AR action for rule 100001.");
                    if (wazuh::engine::actions::handle_trigger_active_response_action("poc-engine-ar", event, EXECQUEUE)) {
                         LOG_INFO_L(lambdaName.c_str(), "PoC AR: Message successfully sent to execd queue for command 'poc-engine-ar'.");
                    } else {
                         LOG_ERROR_L(lambdaName.c_str(), "PoC AR: Failed to send message to execd queue for command 'poc-engine-ar'.");
                    }
                }
                
                LOG_DEBUG_L(lambdaName.c_str(), "PoC Handler: Posting event to orchestrator: {}", event->str());
                orchestrator->postEvent(std::move(event)); // std::move is fine for std::shared_ptr
                
                res.status = httplib::StatusCode::OK_200;
                res.set_content("{\"message\": \"Event received by PoC handler\"}", "application/json");
            };
            LOG_INFO("Using PoC NDJSON handler for /events/stateless");
            g_engineServer->addRoute(httpsrv::Method::POST, "/events/stateless", pocNdjsonPushEventHandler);
#else
            g_engineServer->addRoute(
                httpsrv::Method::POST,
                "/events/stateless",
                api::event::handlers::pushEvent(orchestrator, api::event::protocol::getNDJsonParser(), archiver));
#endif
        }
    }
    catch (const std::exception& e)
    {
        const auto msg = utils::getExceptionStack(e);
        LOG_ERROR("An error occurred while initializing the modules: {}.", msg);
        exitHandler.execute();
        exit(EXIT_FAILURE);
    }

    // Start server
    try
    {
        g_engineServer->start(confManager.get<std::string>(conf::key::SERVER_EVENT_SOCKET),
                              false); // Start in this thread
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("An error occurred while running the server: {}.", utils::getExceptionStack(e));
    }

    // Clean exit
    exitHandler.execute();
}
