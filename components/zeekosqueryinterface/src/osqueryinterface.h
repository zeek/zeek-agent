#pragma once

#include <zeek/iosqueryinterface.h>

namespace zeek {
class OsqueryInterface final : public IOsqueryInterface {
public:
  virtual ~OsqueryInterface() override;

  virtual Status start() override;
  virtual void stop() override;

protected:
  OsqueryInterface(IVirtualDatabase &virtual_database, IZeekLogger &logger);

private:
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

  friend class IOsqueryInterface;
};
} // namespace zeek
