#pragma once

#include <zeek/ivirtualdatabase.h>

namespace zeek {
/// \brief Virtual database (implementation)
class VirtualDatabase final : public IVirtualDatabase {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  /// \brief Destructor
  virtual ~VirtualDatabase() override;

  /// \return A list of registered virtual tables
  virtual std::vector<std::string> virtualTableList() const override;

  /// \brief Registers the given table inside the virtual database
  /// \param table An IVirtualTable plugin
  /// \return A Status object
  virtual Status registerTable(IVirtualTable::Ref table) override;

  /// \brief Unregisters the specified table from the database
  /// \param name The name of the table to unregister
  /// \return A Status object
  virtual Status unregisterTable(const std::string &name) override;

  /// \brief Queries the virtual database
  /// \param output Where the query output is stored
  /// \param query The SQL statement to execute
  /// \return A Status object
  virtual Status query(QueryOutput &output,
                       const std::string &query) const override;

protected:
  /// \brief Constructor
  VirtualDatabase();

  friend class IVirtualDatabase;

public:
  /// \brief Validates the given table name
  /// \return A Status object
  static Status validateTableName(const std::string &name);

  /// \brief Validates the given table schema
  /// \return A Status object
  static Status validateTableSchema(const IVirtualTable::Schema &schema);
};
} // namespace zeek
