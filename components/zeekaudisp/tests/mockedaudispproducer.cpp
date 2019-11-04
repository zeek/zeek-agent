#include "mockedaudispproducer.h"

namespace zeek {
struct MockedAudispProducer::PrivateData final {
  std::string event_buffer;
};

Status MockedAudispProducer::create(IAudispProducer::Ref &obj,
                                    const std::string &event_buffer) {
  obj.reset();

  try {
    auto ptr = new MockedAudispProducer(event_buffer);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

MockedAudispProducer::~MockedAudispProducer() {}

Status MockedAudispProducer::read(std::string &buffer) {
  if (d->event_buffer.empty()) {
    throw std::runtime_error("Reading past the end of the buffer");
  }

  buffer = std::move(d->event_buffer);
  d->event_buffer = {};

  return Status::success();
}

MockedAudispProducer::MockedAudispProducer(const std::string &event_buffer)
    : d(new PrivateData) {
  if (event_buffer.empty()) {
    throw Status::failure("Invalid event buffer");
  }

  d->event_buffer = event_buffer;
}
} // namespace zeek
