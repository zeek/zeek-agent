#include "audispconsumer.h"
#include "mockedauparseinterface.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("AudispConsumer record parsers", "[AudispConsumer]") {
  GIVEN("a valid AUDIT_SYSCALL record for an execve event") {
    // clang-format off
    static const MockedAuparseInterface::FieldList kAuditSyscallRecord = {
      { "type", "1300" },
      { "arch", "c000003e" },
      { "syscall", "59" },
      { "success", "yes" },
      { "exit", "0" },
      { "a0", "23eb8e0" },
      { "a1", "23ebbc0" },
      { "a2", "23c9860" },
      { "a3", "7ffe18d32ed0" },
      { "items", "2" },
      { "ppid", "6882" },
      { "pid", "7841" },
      { "auid", "1000" },
      { "uid", "1000" },
      { "gid", "1000" },
      { "euid", "1000" },
      { "suid", "1000" },
      { "fsuid", "1000" },
      { "egid", "1000" },
      { "sgid", "1000" },
      { "fsgid", "1000" },
      { "tty", "pts1" },
      { "ses", "2" },
      { "comm", "\"sh\"" },
      { "exe", "\"/usr/bin/bash\"" },
      { "subj", "unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023" },
      { "key", "(null)" }
    };
    // clang-format on

    MockedAuparseInterface::Ref auparse;
    auto status = MockedAuparseInterface::create(auparse, kAuditSyscallRecord);
    REQUIRE(status.succeeded());

    WHEN("parsing the event record") {
      std::optional<AudispConsumer::SyscallRecordData> optional_data;
      status = AudispConsumer::parseSyscallRecord(optional_data, auparse);

      REQUIRE(status.succeeded());

      THEN("record data is captured correctly") {
        REQUIRE(optional_data.has_value());

        const auto &data = optional_data.value();
        REQUIRE(data.type == AudispConsumer::SyscallRecordData::Type::Execve);

        REQUIRE(data.exit_code == 0);
        REQUIRE(data.process_id == 7841);
        REQUIRE(data.parent_process_id == 6882);
        REQUIRE(data.succeeded);
      }
    }
  }

  GIVEN("a list of AUDIT_EXECVE records with split arguments") {
    // clang-format off
    static const MockedAuparseInterface::FieldList kAuditExecveRecord01 = {
      { "type", "1309" },
      { "argc", "4" },
      { "a0", "arg_0" }
    };
    // clang-format on

    // clang-format off
    static const MockedAuparseInterface::FieldList kAuditExecveRecord02 = {
      { "type", "1309" },
      { "a1_len", "5" },
      { "a1[0]", "arg" }
    };
    // clang-format on

    // clang-format off
    static const MockedAuparseInterface::FieldList kAuditExecveRecord03 = {
      { "type", "1309" },
      { "a1[1]", "_1" }
    };
    // clang-format on

    // clang-format off
    static const MockedAuparseInterface::FieldList kAuditExecveRecord04 = {
      { "type", "1309" },
      { "a2", "arg_2" },
      { "a3", "arg_3" }
    };
    // clang-format on

    // clang-format off
    static const std::vector<MockedAuparseInterface::FieldList> kAuditExecveRecordList = {
      kAuditExecveRecord01,
      kAuditExecveRecord02,
      kAuditExecveRecord03,
      kAuditExecveRecord04
    };
    // clang-format on

    WHEN("parsing the event records") {
      AudispConsumer::RawExecveRecordData raw_execve_record;

      for (const auto &mocked_record : kAuditExecveRecordList) {
        MockedAuparseInterface::Ref auparse;
        auto status = MockedAuparseInterface::create(auparse, mocked_record);
        REQUIRE(status.succeeded());

        status =
            AudispConsumer::parseRawExecveRecord(raw_execve_record, auparse);

        REQUIRE(status.succeeded());
      }

      REQUIRE(raw_execve_record.argc == 4);
      REQUIRE(raw_execve_record.argument_list.size() == 5U);

      AudispConsumer::ExecveRecordData execve_record;
      auto status =
          AudispConsumer::processExecveRecord(execve_record, raw_execve_record);

      REQUIRE(status.succeeded());

      THEN("record data is captured and assembled correctly") {
        REQUIRE(execve_record.argc == 4);
        REQUIRE(execve_record.argument_list.size() == 4U);

        REQUIRE(execve_record.argument_list.at(0U) == "arg_0");
        REQUIRE(execve_record.argument_list.at(1U) == "arg_1");
        REQUIRE(execve_record.argument_list.at(2U) == "arg_2");
        REQUIRE(execve_record.argument_list.at(3U) == "arg_3");
      }
    }
  }
}
} // namespace zeek
