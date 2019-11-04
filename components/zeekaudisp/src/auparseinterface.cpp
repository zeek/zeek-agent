#include "auparseinterface.h"

namespace zeek {
struct AuparseInterface::PrivateData final {
  auparse_state_t *auparse_state{nullptr};
};

Status AuparseInterface::create(Ref &obj) {
  obj.reset();

  try {
    auto ptr = new AuparseInterface();
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

AuparseInterface::~AuparseInterface() {
  auparse_destroy(d->auparse_state);
  d->auparse_state = nullptr;
}

int AuparseInterface::flushFeed() {
  return auparse_flush_feed(d->auparse_state);
}

int AuparseInterface::feed(const char *data, size_t data_len) {
  return auparse_feed(d->auparse_state, data, data_len);
}

int AuparseInterface::firstField() {
  return auparse_first_field(d->auparse_state);
}

const char *AuparseInterface::getFieldName() {
  return auparse_get_field_name(d->auparse_state);
}

const char *AuparseInterface::getFieldStr() {
  return auparse_get_field_str(d->auparse_state);
}

int AuparseInterface::nextField() {
  return auparse_next_field(d->auparse_state);
}

int AuparseInterface::firstRecord() {
  return auparse_first_record(d->auparse_state);
}

int AuparseInterface::getType() { return auparse_get_type(d->auparse_state); }

int AuparseInterface::nextRecord() {
  return auparse_next_record(d->auparse_state);
}

unsigned int AuparseInterface::getNumRecords() {
  return auparse_get_num_records(d->auparse_state);
}

int AuparseInterface::gotoRecordNum(unsigned int num) {
  return auparse_goto_record_num(d->auparse_state, num);
}

void AuparseInterface::addCallback(auparse_callback_ptr callback,
                                   void *user_data,
                                   user_destroy user_destroy_func) {
  return auparse_add_callback(d->auparse_state, callback, user_data,
                              user_destroy_func);
}

AuparseInterface::AuparseInterface() : d(new PrivateData) {
  d->auparse_state = auparse_init(AUSOURCE_FEED, 0);
  if (d->auparse_state == nullptr) {
    throw Status::failure("Failed to create the auparse state object");
  }
}
} // namespace zeek
