#pragma once

#include <string>

namespace zeek {
class Status final {
  bool succeeded_{false};
  std::string message_;

public:
  Status() : succeeded_{false} {}

  bool succeeded() const { return succeeded_; }
  const std::string &message() const { return message_; }

  static Status success(const std::string &message = std::string()) {
    return Status(true, message);
  }

  static Status failure(const std::string &message = std::string()) {
    return Status(false, message);
  }

private:
  Status(bool succeeded, const std::string &message)
      : succeeded_{succeeded}, message_(message) {}
};
} // namespace zeek
