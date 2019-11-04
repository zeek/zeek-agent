#pragma once

#include "iaudispproducer.h"

#include <memory>

namespace zeek {
class MockedAudispProducer final : public IAudispProducer {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  static Status create(IAudispProducer::Ref &obj,
                       const std::string &socket_path);
  virtual ~MockedAudispProducer() override;

  virtual Status read(std::string &buffer) override;

protected:
  MockedAudispProducer(const std::string &socket_path);
};
} // namespace zeek
