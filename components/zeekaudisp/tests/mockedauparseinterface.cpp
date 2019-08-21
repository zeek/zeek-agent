#include "mockedauparseinterface.h"

namespace zeek {
struct MockedAuparseInterface::PrivateData final {
  FieldList field_list;
  std::size_t current_field{0U};
};

Status MockedAuparseInterface::create(Ref &obj, const FieldList &field_list) {
  obj.reset();

  try {
    auto ptr = new MockedAuparseInterface(field_list);
    obj.reset(ptr);

    return Status::success();

  } catch (const std::bad_alloc &) {
    return Status::failure("Memory allocation failure");

  } catch (const Status &status) {
    return status;
  }
}

MockedAuparseInterface::~MockedAuparseInterface() {}

int MockedAuparseInterface::firstField() {
  d->current_field = 0U;
  return 0;
}

int MockedAuparseInterface::nextField() {
  ++d->current_field;

  if (d->current_field >= d->field_list.size()) {
    return 0;
  }

  return 1;
}

const char *MockedAuparseInterface::getFieldName() {
  if (d->current_field >= d->field_list.size()) {
    throw std::runtime_error("Reached the end of the field list");
  }

  const auto &field_desc = d->field_list.at(d->current_field);
  const auto &field_name = field_desc.first;

  return field_name.c_str();
}

const char *MockedAuparseInterface::getFieldStr() {
  if (d->current_field >= d->field_list.size()) {
    throw std::runtime_error("Reached the end of the field list");
  }

  const auto &field_desc = d->field_list.at(d->current_field);
  const auto &field_value = field_desc.second;

  return field_value.c_str();
}

int MockedAuparseInterface::firstRecord() { return 0; }

int MockedAuparseInterface::flushFeed() { return 0; }

int MockedAuparseInterface::feed(const char *, size_t) { return 0; }

int MockedAuparseInterface::getType() { return 0; }

int MockedAuparseInterface::nextRecord() { return 0; }

unsigned int MockedAuparseInterface::getNumRecords() { return 0U; }

int MockedAuparseInterface::gotoRecordNum(unsigned int) { return 0; }

void MockedAuparseInterface::addCallback(auparse_callback_ptr, void *,
                                         user_destroy) {}

MockedAuparseInterface::MockedAuparseInterface(const FieldList &field_list)
    : d(new PrivateData) {
  d->field_list = field_list;
}
} // namespace zeek
