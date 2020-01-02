#pragma once

#include <zeek/ivirtualtable.h>
#include <zeek/izeekconfiguration.h>

namespace zeek {
/// \brief A virtual table plugin that exposes the given configuration object
class ZeekConfigurationTablePlugin final : public IVirtualTable {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \param configuration A reference to an initialized configuration object
  /// \return A Status object
  static Status create(Ref &obj, IZeekConfiguration &configuration);

  /// \brief Destructor
  virtual ~ZeekConfigurationTablePlugin() override;

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
  /// \param configuration A reference to an initialized configuration object
  ZeekConfigurationTablePlugin(IZeekConfiguration &configuration);
};
} // namespace zeek
