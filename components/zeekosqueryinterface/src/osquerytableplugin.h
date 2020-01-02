#pragma once

#include <zeek/ivirtualtable.h>
#include <zeek/izeeklogger.h>

namespace zeek {
/// \brief A table plugin that forwards an osquery table
///        to the Zeek Agent database
class OsqueryTablePlugin final : public IVirtualTable {
public:
  /// \brief Factory method
  /// \param ref Where the created object is stored
  /// \param osquery_table_name The name of the osquery table to import
  /// \param logger A reference to a valid logger instance
  /// \return A Status object
  static Status create(Ref &ref, const std::string &osquery_table_name,
                       IZeekLogger &logger);

  /// \brief Destructor
  virtual ~OsqueryTablePlugin() override;

  /// \return The table name
  virtual const std::string &name() const override;

  /// \return The table schema
  virtual const Schema &schema() const override;

  /// \brief Generates the row list containing the logged messages
  /// \param row_list Where the generated rows are stored
  /// \return A Status object
  virtual Status generateRowList(RowList &row_list) override;

protected:
  /// \brief Constructor
  /// \param osquery_table_name The name of the osquery table to import
  /// \param logger A reference to a valid logger instance
  OsqueryTablePlugin(const std::string &osquery_table_name,
                     IZeekLogger &logger);

  struct PrivateData;
  std::unique_ptr<PrivateData> d;
};
} // namespace zeek
