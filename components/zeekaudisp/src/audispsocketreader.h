#pragma once

#include "iaudispproducer.h"

#include <memory>

#include <zeek/status.h>

namespace zeek {
class AudispSocketReader final : public IAudispProducer {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static Status create(IAudispProducer::Ref &obj,
                       const std::string &socket_path);

  virtual ~AudispSocketReader() override;

  virtual Status read(std::string &buffer) override;

protected:
  AudispSocketReader(const std::string &socket_path);
};
} // namespace zeek
