#pragma once

#include <zeek/ivirtualdatabase.h>

namespace zeek {
class IZeekLogger {
public:
  enum class Severity { Debug, Information, Warning, Error };

  struct Configuration final {
    Severity severity_filter{Severity::Information};
    std::string log_folder;
  };

  using Ref = std::unique_ptr<IZeekLogger>;
  static Status create(Ref &ref, const Configuration &configuration,
                       IVirtualDatabase &virtual_database);

  IZeekLogger() = default;
  virtual ~IZeekLogger() = default;

  virtual void logMessage(Severity severity, const std::string &message) = 0;

  IZeekLogger(const IZeekLogger &) = delete;
  IZeekLogger &operator=(const IZeekLogger &) = delete;
};

const std::string &
loggerSeverityToString(const IZeekLogger::Severity &severity);
} // namespace zeek
