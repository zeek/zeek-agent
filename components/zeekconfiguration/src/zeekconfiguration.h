#pragma once

#include <zeek/izeekconfiguration.h>

namespace zeek {
/// \brief Configuration class (implementation)
class ZeekConfiguration final : public IZeekConfiguration {
public:
  /// \brief Destructor
  virtual ~ZeekConfiguration() override;

  /// \return Returns the configured server address
  virtual const std::string &serverAddress() const override;

  /// \return Returns the configured server port
  virtual std::uint16_t serverPort() const override;

  /// \brief Returns a list of Zeek groups to be joined on startup
  /// \return Returns the configured group list
  virtual const std::vector<std::string> &groupList() const override;

  /// \return Returns the configured log folder
  virtual const std::string &getLogFolder() const override;

  /// \return Returns the path for the configured certificate authority
  virtual const std::string &certificateAuthority() const override;

  /// \return Returns the path for the configured client certificate
  virtual const std::string &clientCertificate() const override;

  /// \return Returns the path for the configured client key
  virtual const std::string &clientKey() const override;

  /// \return Returns the path for the configured osquery extensions socket
  virtual const std::string &osqueryExtensionsSocket() const override;

  /// \return Returns the maximum number of rows that can be queued in a table
  ///         that is waiting to be queried
  virtual std::size_t maxQueuedRowCount() const override;

protected:
  /// \brief Constructor
  /// \param virtual_database A reference to a virtual database instance. Used
  ///                         to export the configuration
  /// \param configuration_file_path Path to the configuration file
  ZeekConfiguration(IVirtualDatabase &virtual_database,
                    const std::string &configuration_file_path);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  /// \brief Registers the configuration table
  /// \return A Status object
  Status registerTables();

  /// \brief Unregisters the configuration table
  /// \return A Status object
  Status unregisterTables();

  /// \brief Loads the configuration from the specified file path
  /// \return A Status object
  Status loadConfigurationFile(const std::string &configuration_file_path);

  friend class IZeekConfiguration;

public:
  /// \brief Contains all the configurable fields
  struct Context final {
    /// \brief Server address
    std::string server_address;

    /// \brief Server port
    std::uint16_t server_port;

    /// \brief Path to the log folder
    std::string log_folder;

    /// \brief List of Zeek groups to join on startup
    std::vector<std::string> group_list;

    /// \brief Path to the configured certificate authority
    std::string certificate_authority;

    /// \brief Path to the configured client certificate
    std::string client_certificate;

    /// \brief Path to the configured client key
    std::string client_key;

    /// \brief Path to the osquery extensions socket
    std::string osquery_extensions_socket;

    /// \brief Maximum amount of rows that can be queued in a table that is
    /// waiting to be queried
    std::size_t max_queued_row_count;
  };

  /// \brief Parses the given configuration data in JSON format
  /// \param context Where the parsed configuration fields are stored
  /// \param json The contents of the configuration file
  /// \param A Status object
  static Status parseConfigurationData(Context &context,
                                       const std::string &json);
};
} // namespace zeek
