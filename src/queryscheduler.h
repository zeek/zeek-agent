#pragma once

#include <atomic>
#include <memory>

#include <zeek/ivirtualdatabase.h>
#include <zeek/status.h>

namespace zeek {
class QueryScheduler final {
  struct PrivateData;
  std::unique_ptr<PrivateData> d;

public:
  using Ref = std::unique_ptr<QueryScheduler>;

  static Status create(Ref &obj, IVirtualDatabase &virtual_database);
  ~QueryScheduler();

  struct Task final {
    enum class Type { AddScheduledQuery, RemoveScheduledQuery, ExecuteQuery };
    enum class UpdateType { Added, Removed, Both };

    Type type;
    std::string query;
    std::string response_event;
    std::string response_topic;
    std::string cookie;
    std::optional<std::uint64_t> interval;
    std::optional<UpdateType> update_type;
  };

  using TaskQueue = std::vector<Task>;

  struct TaskOutput final {
    std::string response_topic;
    std::string response_event;

    std::string cookie;
    std::optional<Task::UpdateType> update_type;

    IVirtualDatabase::QueryOutput query_output;
  };

  using TaskOutputList = std::vector<TaskOutput>;

  void processTaskQueue(TaskQueue task_queue);
  Status processEvents();
  TaskOutputList getTaskOutputList();

  Status start();
  void stop();

  QueryScheduler(const QueryScheduler &) = delete;
  QueryScheduler &operator=(const QueryScheduler &) = delete;

protected:
  QueryScheduler(IVirtualDatabase &virtual_database);

private:
  Status executeTask(const Task &task);
};
} // namespace zeek
