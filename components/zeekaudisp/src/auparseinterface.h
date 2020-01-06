#pragma once

#include "iauparseinterface.h"

#include <zeek/status.h>

namespace zeek {
/// \brief auparse interface (interface). See the auparse docs for more
/// information
class AuparseInterface final : public IAuparseInterface {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// Factory
  static Status create(Ref &obj);
  virtual ~AuparseInterface();

  virtual int flushFeed() override;
  virtual int feed(const char *data, size_t data_len) override;
  virtual int firstField() override;
  virtual const char *getFieldName() override;
  virtual const char *getFieldStr() override;
  virtual int nextField() override;
  virtual int firstRecord() override;
  virtual int getType() override;
  virtual int nextRecord() override;
  virtual int nextEvent() override;

  virtual void addCallback(auparse_callback_ptr callback, void *user_data,
                           user_destroy user_destroy_func) override;

protected:
  AuparseInterface();
};
} // namespace zeek
