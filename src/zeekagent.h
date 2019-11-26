#pragma once

#include "zeekconnection.h"

#include <atomic>
#include <memory>

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeekservicemanager.h>

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
  Status initializeConnection(ZeekConnection::Ref &zeek_connection);
  Status initializeQueryScheduler(QueryScheduler::Ref &query_scheduler);
  Status initializeServiceManager(IZeekServiceManager::Ref &service_manager);

  Status startServices();
  void stopServices();
};
} // namespace zeek
