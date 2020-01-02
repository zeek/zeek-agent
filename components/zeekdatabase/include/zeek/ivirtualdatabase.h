#pragma once

#include <memory>
#include <vector>

#include <zeek/ivirtualtable.h>
#include <zeek/status.h>

namespace zeek {
/// \brief Virtual database (interface)
class IVirtualDatabase {
public:
  /// \brief A column value, used with IVirtualDatabase::OutputRow
  struct ColumnValue final {
    /// \brief Column name
    std::string name;

    /// \brief An std::variant within an std::optional containing
    ///        the column value.
    IVirtualTable::OptionalVariant data;
  };

  /// \brief A generated table row, made of many ColumnValue object
  using OutputRow = std::vector<ColumnValue>;

  /// \brief A list of generated rows, made of many OutputRow objects
  using QueryOutput = std::vector<OutputRow>;

  /// \brief A reference to a virtual database object
  using Ref = std::unique_ptr<IVirtualDatabase>;

  /// \brief Factory method
  /// \param obj Where the created object is stored
  /// \return A Status object
  static Status create(Ref &obj);

  /// \brief Constructor
  IVirtualDatabase() = default;

  /// \brief Destructor
  virtual ~IVirtualDatabase() = default;

  /// \return A list of registered virtual tables
  virtual std::vector<std::string> virtualTableList() const = 0;

  /// \brief Registers the given table inside the virtual database
  /// \param table An IVirtualTable plugin
  /// \return A Status object
  virtual Status registerTable(IVirtualTable::Ref table) = 0;

  /// \brief Unregisters the specified table from the database
  /// \param name The name of the table to unregister
  /// \return A Status object
  virtual Status unregisterTable(const std::string &name) = 0;

  /// \brief Queries the virtual database
  /// \param output Where the query output is stored
  /// \param query The SQL statement to execute
  /// \return A Status object
  virtual Status query(QueryOutput &output, const std::string &query) const = 0;

  IVirtualDatabase(const IVirtualDatabase &other) = delete;
  IVirtualDatabase &operator=(const IVirtualDatabase &other) = delete;
};
} // namespace zeek
