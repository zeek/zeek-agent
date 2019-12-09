#pragma once

#include <memory>

#include <zeek/ivirtualdatabase.h>
#include <zeek/izeeklogger.h>

namespace zeek {
class IOsqueryInterface {
public:
  using Ref = std::unique_ptr<IOsqueryInterface>;
  static Status create(Ref &ref, IVirtualDatabase &virtual_database,
                       IZeekLogger &logger,
                       const std::string &extensions_socket);

  IOsqueryInterface() = default;
  virtual ~IOsqueryInterface() = default;

  virtual Status start() = 0;
  virtual void stop() = 0;

  IOsqueryInterface(const IOsqueryInterface &) = delete;
  IOsqueryInterface &operator=(const IOsqueryInterface &) = delete;
};
} // namespace zeek
