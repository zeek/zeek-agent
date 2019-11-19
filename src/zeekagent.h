#pragma once

#include <atomic>
#include <memory>

#include <zeek/ivirtualdatabase.h>
#include <zeek/status.h>

namespace zeek {
class ZeekAgent final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  using Ref = std::unique_ptr<ZeekAgent>;

  static Status create(Ref &obj);
  ~ZeekAgent();

  Status exec(std::atomic_bool &terminate);

  IVirtualDatabase &virtualDatabase();

  ZeekAgent(const ZeekAgent &) = delete;
  ZeekAgent &operator=(const ZeekAgent &) = delete;

protected:
  ZeekAgent();

private:
  Status initializeConnection();
  Status initializeServiceManager();

  Status startServices();
  void stopServices();
};
} // namespace zeek
