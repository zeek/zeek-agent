#pragma once

#include <zeek/izeeklogger.h>

namespace zeek {
/// \brief The Zeek logger (implementation)
class ZeekLogger final : public IZeekLogger {
public:
  /// \brief Destructor
  virtual ~ZeekLogger() override;

  /// \brief Logs a message both to file and to the log table
  /// \param severity The log severity
  /// \param message The message to log
  virtual void logMessage(Severity severity,
                          const std::string &message) override;

protected:
  /// \brief Constructor
  /// \param ref Where the created object is stored
  /// \param configuration How the logger should be configured
  /// \param virtual_database The virtual database object, used to
  ///                         publish the logs to a table
  ZeekLogger(const Configuration &configuration,
             IVirtualDatabase &virtual_database);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  /// \brief Registers the zeek_logger table to the database
  /// \return A Status object
  Status registerTables();

  /// \brief Unregisters the zeek_logger table from the database
  /// \return A Status object
  Status unregisterTables();

  friend class IZeekLogger;
};
} // namespace zeek
