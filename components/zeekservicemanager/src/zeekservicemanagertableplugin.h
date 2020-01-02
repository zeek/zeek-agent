#pragma once

#include <zeek/ivirtualtable.h>
#include <zeek/izeekservicemanager.h>

namespace zeek {
/// \brief A Virtual table plugin that lists the running Zeek services
class ZeekServiceManagerTablePlugin final : public IVirtualTable {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \param service_manager A reference to an initialized service manager
  /// \return A Status object
  static Status create(Ref &obj, IZeekServiceManager &service_manager);

  /// \brief Destructor
  virtual ~ZeekServiceManagerTablePlugin() override;

  /// \return The table name
  virtual const std::string &name() const override;

  /// \return The table schema
  virtual const Schema &schema() const override;

  /// \brief Generates the row list containing the fields from the given
  ///        configuration object
  /// \param row_list Where the generated rows are stored
  /// \return A Status object
  virtual Status generateRowList(RowList &row_list) override;

protected:
  /// \brief Constructor
  /// \param service_manager A reference to an initialized service manager
  ZeekServiceManagerTablePlugin(IZeekServiceManager &service_manager);
};
} // namespace zeek
