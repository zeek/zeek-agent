#pragma once

#include <string>

namespace zeek {
/// \brief A Status object, containing an error code and a message
class Status final {
  /// \brief True if the operation has succeeded
  bool succeeded_{false};

  /// \brief Error message
  std::string message_;

public:
  /// \brief Constructor, default initializing to a failure
  Status() : succeeded_{false} {}

  /// \return True if the operation has succeeded
  bool succeeded() const { return succeeded_; }

  /// \return The status message
  const std::string &message() const { return message_; }

  /// \brief Factory method creating a successful status
  static Status success(const std::string &message = std::string()) {
    return Status(true, message);
  }

  /// \brief Factory method creating a failure status
  static Status failure(const std::string &message = std::string()) {
    return Status(false, message);
  }

private:
  /// \brief Constructor
  /// \param succeeded True if the operation has succeed, or
  ///                  false otherwise
  /// \param message The status message
  Status(bool succeeded, const std::string &message)
      : succeeded_{succeeded}, message_(message) {}
};
} // namespace zeek
