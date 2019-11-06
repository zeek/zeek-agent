#include "audispsocketreader.h"

#include <cstring>
#include <vector>

//#include <asm/unistd.h>
#include <libaudit.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace zeek {
namespace {
const int kPollTimeout{1000};
const std::size_t kReadBufferSize{MAX_AUDIT_MESSAGE_LENGTH};
} // namespace

struct AudispSocketReader::PrivateData final {
  std::string unix_socket_path;
  int socket{-1};
  std::vector<char> read_buffer;
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

AudispSocketReader::~AudispSocketReader() { close(d->socket); }

Status AudispSocketReader::read(std::string &buffer) {
  buffer.reserve(kReadBufferSize);

  struct pollfd pfd = {};
  pfd.events = POLLIN;
  pfd.fd = d->socket;

  auto err = poll(&pfd, 1, kPollTimeout);
  if (err < 0) {
    if (errno == EINTR) {
      return Status::success();
    }

    return Status::failure("poll() has failed with error " +
                           std::to_string(err) + "/" + std::to_string(errno));

  } else if (err == 0) {
    return Status::success();
  }

  if ((pfd.revents & POLLIN) == 0) {
    return Status::success();
  }

  err = ::read(pfd.fd, d->read_buffer.data(), kReadBufferSize);
  if (err <= 0) {
    return Status::failure("read() has failed with error " +
                           std::to_string(err) + "/" + std::to_string(errno));
  }

  buffer.assign(d->read_buffer.data(), 0U, static_cast<std::size_t>(err));
  return Status::success();
}

AudispSocketReader::AudispSocketReader(const std::string &socket_path)
    : d(new PrivateData) {
  d->unix_socket_path = socket_path;
  d->read_buffer.resize(kReadBufferSize + 1U);

  d->socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (d->socket == -1) {
    throw Status::failure("Failed to create the socket");
  }

  struct sockaddr_un address = {};
  address.sun_family = AF_UNIX;
  std::strcpy(address.sun_path, d->unix_socket_path.data());

  if (connect(d->socket, reinterpret_cast<struct sockaddr *>(&address),
              sizeof(address)) != 0) {
    throw Status::failure("Connection failure");
  }
}
} // namespace zeek
