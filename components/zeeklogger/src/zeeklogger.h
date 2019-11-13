#pragma once

#include <memory>

#include <zeek/izeeklogger.h>

namespace zeek {
class ZeekLogger final : public IZeekLogger {
public:
  virtual ~ZeekLogger() override;

  virtual void logMessage(Severity severity,
                          const std::string &message) override;

protected:
  ZeekLogger(const Configuration &configuration,
             IVirtualDatabase &virtual_database);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  Status registerTables();
  Status unregisterTables();

  friend class IZeekLogger;
};
} // namespace zeek
