#pragma once

#include <memory>

#include <zeek/ivirtualdatabase.h>

namespace zeek {
/// \brief The Zeek logger (interface)
class IZeekLogger {
public:
  /// \brief Supported severity types
  enum class Severity { Debug, Information, Warning, Error };

  /// \brief The logger configuration
  struct Configuration final {
    /// \brief Severity filter
    Severity severity_filter{Severity::Information};

    /// \brief The path to the log folder
    std::string log_folder;
  };

  /// \brief A reference to a Zeek logger object
  using Ref = std::unique_ptr<IZeekLogger>;

  /// \brief Factory method
  /// \param ref Where the created object is stored
  /// \param configuration How the logger should be configured
  /// \param virtual_database The virtual database object, used to
  ///                         publish the logs to a table
  /// \return A Status object
  static Status create(Ref &ref, const Configuration &configuration,
                       IVirtualDatabase &virtual_database);

  /// \brief Constructor
  IZeekLogger() = default;

  /// \brief Destructor
  virtual ~IZeekLogger() = default;

  /// \brief Logs a message both to file and to the log table
  /// \param severity The log severity
  /// \param message The message to log
  virtual void logMessage(Severity severity, const std::string &message) = 0;

  IZeekLogger(const IZeekLogger &) = delete;
  IZeekLogger &operator=(const IZeekLogger &) = delete;
};

/// \param severity The severity id
/// \return Converts a severity id to a string
const std::string &
loggerSeverityToString(const IZeekLogger::Severity &severity);
} // namespace zeek
