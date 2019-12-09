#pragma once

#include <zeek/izeekconfiguration.h>

namespace zeek {
class ZeekConfiguration final : public IZeekConfiguration {
public:
  virtual ~ZeekConfiguration() override;

  virtual const std::string &serverAddress() const override;
  virtual std::uint16_t serverPort() const override;
  virtual const std::vector<std::string> &groupList() const override;

  virtual const std::string &getLogFolder() const override;

  virtual const std::string &certificateAuthority() const override;
  virtual const std::string &clientCertificate() const override;
  virtual const std::string &clientKey() const override;

  virtual const std::string &osqueryExtensionsSocket() const override;

protected:
  ZeekConfiguration(IVirtualDatabase &virtual_database,
                    const std::string &configuration_file_path);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  Status registerTables();
  Status unregisterTables();
  Status loadConfigurationFile(const std::string &configuration_file_path);

  friend class IZeekConfiguration;

public:
  struct Context final {
    std::string server_address;
    std::uint16_t server_port;
    std::string log_folder;
    std::vector<std::string> group_list;
    std::string certificate_authority;
    std::string client_certificate;
    std::string client_key;
    std::string osquery_extensions_socket;
  };

  static Status parseConfigurationData(Context &context,
                                       const std::string &json);
};
} // namespace zeek
