#include "iauparseinterface.h"

#include <memory>
#include <vector>

#include <zeek/status.h>

namespace zeek {
class MockedAuparseInterface : public IAuparseInterface {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  using RecordField = std::pair<std::string, std::string>;
  using FieldList = std::vector<RecordField>;

  static Status create(Ref &obj, const FieldList &field_list);
  virtual ~MockedAuparseInterface() override;

  virtual int firstField() override;
  virtual int nextField() override;
  virtual const char *getFieldName() override;
  virtual const char *getFieldStr() override;

  virtual int firstRecord() override;
  virtual int flushFeed() override;
  virtual int feed(const char *, size_t) override;
  virtual int getType() override;
  virtual int nextRecord() override;
  virtual unsigned int getNumRecords() override;
  virtual int gotoRecordNum(unsigned int) override;
  virtual void addCallback(auparse_callback_ptr, void *, user_destroy) override;

protected:
  MockedAuparseInterface(const FieldList &field_list);
};
} // namespace zeek
