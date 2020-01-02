#pragma once

#include <memory>

#include <auparse.h>

namespace zeek {
/// \brief auparse interface (interface). See the auparse docs for more
/// information
class IAuparseInterface {
public:
  using Ref = std::shared_ptr<IAuparseInterface>;

  virtual int flushFeed() = 0;
  virtual int feed(const char *data, size_t data_len) = 0;
  virtual int firstField() = 0;
  virtual const char *getFieldName() = 0;
  virtual const char *getFieldStr() = 0;
  virtual int nextField() = 0;
  virtual int firstRecord() = 0;
  virtual int getType() = 0;
  virtual int nextRecord() = 0;
  virtual unsigned int getNumRecords() = 0;
  virtual int gotoRecordNum(unsigned int num) = 0;

  virtual void addCallback(auparse_callback_ptr callback, void *user_data,
                           user_destroy user_destroy_func) = 0;

  IAuparseInterface() = default;
  virtual ~IAuparseInterface() = default;

  IAuparseInterface(const IAuparseInterface &other) = delete;
  IAuparseInterface &operator=(const IAuparseInterface &other) = delete;
};
} // namespace zeek
