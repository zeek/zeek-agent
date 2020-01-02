#pragma once

#include <memory>

#include <auparse.h>

#include <zeek/status.h>

namespace zeek {
/// \brief Audisp socket reader (interface)
class IAudispProducer {
public:
  using Ref = std::unique_ptr<IAudispProducer>;

  /// \brief Constructor
  IAudispProducer() = default;

  /// \brief Destructor
  virtual ~IAudispProducer() = default;

  /// \brief Acquires new data from the Audisp socket
  /// \param buffer Where the read data is stored
  /// \return A Status object
  virtual Status read(std::string &buffer) = 0;

  IAudispProducer(const IAudispProducer &other) = delete;
  IAudispProducer &operator=(const IAudispProducer &other) = delete;
};
} // namespace zeek
