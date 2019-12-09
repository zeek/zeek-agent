#pragma once

#include <zeek/ivirtualdatabase.h>

namespace zeek {
class IZeekConfiguration {
public:
  using Ref = std::unique_ptr<IZeekConfiguration>;
  static Status create(Ref &ref, IVirtualDatabase &virtual_database,
                       const std::string &configuration_file_path);

  IZeekConfiguration() = default;
  virtual ~IZeekConfiguration() = default;

  virtual const std::string &serverAddress() const = 0;
  virtual std::uint16_t serverPort() const = 0;
  virtual const std::vector<std::string> &groupList() const = 0;

  virtual const std::string &getLogFolder() const = 0;

  virtual const std::string &certificateAuthority() const = 0;
  virtual const std::string &clientCertificate() const = 0;
  virtual const std::string &clientKey() const = 0;

  virtual const std::string &osqueryExtensionsSocket() const = 0;
  virtual std::size_t maxQueuedRowCount() const = 0;

  IZeekConfiguration(const IZeekConfiguration &) = delete;
  IZeekConfiguration &operator=(const IZeekConfiguration &) = delete;
};
} // namespace zeek
