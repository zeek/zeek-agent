#pragma once

#include <memory>

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeeklogger.h>

namespace zeek {
/// \brief A service that forwards osquery tables to the
///        Zeek database (implementation)
class IOsqueryInterface {
public:
  /// \brief A reference to an osquery interface object
  using Ref = std::unique_ptr<IOsqueryInterface>;

  /// \brief Factory method
  /// \param virtual_database A valid virtual database instance
  /// \param logger A valid logger object
  /// \param extensions_socket The path to the osquery extensions socket
  /// \return A Status object
  static Status create(Ref &ref, IVirtualDatabase &virtual_database,
                       IZeekLogger &logger,
                       const std::string &extensions_socket);

  /// \brief Constructor
  IOsqueryInterface() = default;

  /// \brief Destructor
  virtual ~IOsqueryInterface() = default;

  /// \brief Starts the service
  /// \return A Status object
  virtual Status start() = 0;

  /// \brief Stops the service
  virtual void stop() = 0;

  IOsqueryInterface(const IOsqueryInterface &) = delete;
  IOsqueryInterface &operator=(const IOsqueryInterface &) = delete;
};
} // namespace zeek
