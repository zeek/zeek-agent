#pragma once

#include "iaudispproducer.h"

#include <memory>

#include <zeek/status.h>

namespace zeek {
/// \brief Audisp socket reader (implementation)
class AudispSocketReader final : public IAudispProducer {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \param socket_path Path to the Audisp unix domain socket
  /// \return A Status object
  static Status create(IAudispProducer::Ref &obj,
                       const std::string &socket_path);

  /// \brief Destructor
  virtual ~AudispSocketReader() override;

  /// \brief Acquires new data from the Audisp socket
  /// \param buffer Where the read data is stored
  /// \return A Status object
  virtual Status read(std::string &buffer) override;

protected:
  /// \brief Constructor
  /// \param socket_path Path to the Audisp unix domain socket
  AudispSocketReader(const std::string &socket_path);
};
} // namespace zeek
