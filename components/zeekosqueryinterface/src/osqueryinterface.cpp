#include "osqueryinterface.h"
#include "osquerytableplugin.h"
#include "utils.h"

#include <osquery/sdk/sdk.h>
#include <osquery/system.h>

namespace zeek {
struct OsqueryInterface::PrivateData final {
  PrivateData(IVirtualDatabase &virtual_database_, IZeekLogger &logger_)
      : virtual_database(virtual_database_), logger(logger_) {}

  IVirtualDatabase &virtual_database;
  IZeekLogger &logger;
  std::string extensions_socket;

  std::vector<std::string> argv_contents;
  std::vector<char *> argv_pointer_array;

  int extension_runner_argc{0};
  char **extension_runner_argv{nullptr};

  std::unique_ptr<osquery::Initializer> extension_runner;
  std::vector<IVirtualTable::Ref> table_plugin_list;
};

OsqueryInterface::~OsqueryInterface() {}

Status OsqueryInterface::start() {
  if (d->extension_runner) {
    return Status::failure("Already started");
  }

  // Connect to osquery
  d->argv_contents.push_back("zeek-agent");
  d->argv_pointer_array.push_back(&d->argv_contents.back()[0]);

  d->argv_contents.push_back("--extensions_socket=" + d->extensions_socket);
  d->argv_pointer_array.push_back(&d->argv_contents.back()[0]);

  d->argv_pointer_array.push_back(nullptr);

  d->extension_runner_argc = static_cast<int>(d->argv_contents.size());
  d->extension_runner_argv = d->argv_pointer_array.data();

  d->extension_runner = std::make_unique<osquery::Initializer>(
      d->extension_runner_argc, d->extension_runner_argv,
      osquery::ToolType::EXTENSION);

  auto osquery_status = osquery::startExtension("zeek-agent", ZEEK_AGENT_VERSION);
  if (!osquery_status.ok()) {
    return Status::failure("Failed to initialize the extension interface");
  }

  std::vector<std::string> table_list;
  auto status = getOsqueryTableList(table_list);
  if (!status.succeeded()) {
    return status;
  }

  for (const auto &table_name : table_list) {
    auto events_substr_it = table_name.find("events");
    if (events_substr_it != std::string::npos) {
      d->logger.logMessage(IZeekLogger::Severity::Information,
                           "The following table will not be mirrored: " +
                               table_name);

      continue;
    }

    IVirtualTable::Ref table_ref;
    status = OsqueryTablePlugin::create(table_ref, table_name, d->logger);
    if (!status.succeeded()) {
      d->logger.logMessage(IZeekLogger::Severity::Error,
                           "Failed to create the table " + table_name + ": " +
                               status.message());

      continue;
    }

    status = d->virtual_database.registerTable(table_ref);
    if (!status.succeeded()) {
      d->logger.logMessage(IZeekLogger::Severity::Error,
                           "Failed to register the table " + table_name + ": " +
                               status.message());

      continue;
    }

    d->table_plugin_list.push_back(table_ref);
  }

  return Status::success();
}

void OsqueryInterface::stop() {
  if (!d->extension_runner) {
    return;
  }

  // Unregister all the tables
  for (auto &table_ref : d->table_plugin_list) {
    d->virtual_database.unregisterTable(table_ref->name());
  }

  d->table_plugin_list.clear();

  // Stop the extension
  d->extension_runner->requestShutdown(0);

  osquery::Dispatcher::joinServices();
  osquery::EventFactory::end(true);
  GFLAGS_NAMESPACE::ShutDownCommandLineFlags();
  osquery::DatabasePlugin::shutdown();

  d->argv_contents.clear();
  d->argv_pointer_array.clear();
  d->extension_runner_argc = 0;
  d->extension_runner_argv = nullptr;

  d->extension_runner.reset();
}

OsqueryInterface::OsqueryInterface(IVirtualDatabase &virtual_database,
                                   IZeekLogger &logger,
                                   const std::string &extensions_socket)
    : d(new PrivateData(virtual_database, logger)) {

  d->extensions_socket = extensions_socket;
}

Status IOsqueryInterface::create(Ref &ref, IVirtualDatabase &virtual_database,
                                 IZeekLogger &logger,
                                 const std::string &extensions_socket) {
  try {
    ref.reset();

    auto ptr =
        new OsqueryInterface(virtual_database, logger, extensions_socket);
    ref.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}
} // namespace zeek
