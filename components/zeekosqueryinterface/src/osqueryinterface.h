#pragma once

#include <zeek/iosqueryinterface.h>

namespace zeek {
/// \brief A service that forwards osquery tables to the
///        Zeek database (implementation)
class OsqueryInterface final : public IOsqueryInterface {
public:
  /// \brief Destructor
  virtual ~OsqueryInterface() override;

  /// \brief Starts the service
  /// \return A Status object
  virtual Status start() override;

  /// \brief Stops the service
  virtual void stop() override;

protected:
  /// \brief Constructor
  /// \param virtual_database A valid virtual database instance
  /// \param logger A valid logger object
  /// \param extensions_socket The path to the osquery extensions socket
  OsqueryInterface(IVirtualDatabase &virtual_database, IZeekLogger &logger,
                   const std::string &extensions_socket);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  friend class IOsqueryInterface;
};
} // namespace zeek
