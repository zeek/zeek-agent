#pragma once

#include <zeek/ivirtualdatabase.h>

namespace zeek {
/// \brief Configuration class (interface)
class IZeekConfiguration {
public:
  /// \brief A unique reference to a configuration object
  using Ref = std::unique_ptr<IZeekConfiguration>;

  /// \brief Factory method
  /// \param ref Where the output object is stored
  /// \param virtual_database A reference to a virtual database instance. Used
  ///                         to export the configuration
  /// \param configuration_file_path Path to the configuration file
  /// \return A Status object
  static Status create(Ref &ref, IVirtualDatabase &virtual_database,
                       const std::string &configuration_file_path);

  /// \brief Constructor
  IZeekConfiguration() = default;

  /// \brief Destructor
  virtual ~IZeekConfiguration() = default;

  /// \return Returns the configured server address
  virtual const std::string &serverAddress() const = 0;

  /// \return Returns the configured server port
  virtual std::uint16_t serverPort() const = 0;

  /// \brief Returns a list of Zeek groups to be joined on startup
  /// \return Returns the configured group list
  virtual const std::vector<std::string> &groupList() const = 0;

  /// \return Returns the configured log folder
  virtual const std::string &getLogFolder() const = 0;

  /// \return Returns the path for the configured certificate authority
  virtual const std::string &certificateAuthority() const = 0;

  /// \return Returns the path for the configured client certificate
  virtual const std::string &clientCertificate() const = 0;

  /// \return Returns the path for the configured client key
  virtual const std::string &clientKey() const = 0;

  /// \return Returns the path for the configured osquery extensions socket
  virtual const std::string &osqueryExtensionsSocket() const = 0;

  /// \return Returns the maximum number of rows that can be queued in a table
  ///         that is waiting to be queried
  virtual std::size_t maxQueuedRowCount() const = 0;

  IZeekConfiguration(const IZeekConfiguration &) = delete;
  IZeekConfiguration &operator=(const IZeekConfiguration &) = delete;
};
} // namespace zeek
