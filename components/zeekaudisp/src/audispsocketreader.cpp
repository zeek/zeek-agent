#include "audispsocketreader.h"

namespace zeek {
struct AudispSocketReader::PrivateData final {
  std::string socket_path;
};

Status AudispSocketReader::create(IAudispProducer::Ref &obj,
                                  const std::string &socket_path) {
  obj.reset();

  try {
    auto ptr = new AudispSocketReader(socket_path);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

AudispSocketReader::~AudispSocketReader() {}

Status AudispSocketReader::read(std::string &buffer) {
  buffer = {};

  return Status::success();
}

AudispSocketReader::AudispSocketReader(const std::string &socket_path)
    : d(new PrivateData) {
  d->socket_path = socket_path;
}
} // namespace zeek
