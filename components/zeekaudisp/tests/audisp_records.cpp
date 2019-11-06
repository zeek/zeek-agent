#include "audispconsumer.h"
#include "mockedauparseinterface.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("AudispConsumer record parsers", "[AudispConsumer]") {
  GIVEN("a valid AUDIT_SYSCALL record for an execve event") {
    static const std::string kExpectedAuid{"1"};
    static const std::string kExpectedUid{"2"};
    static const std::string kExpectedEuid{"3"};
    static const std::string kExpectedGid{"4"};
    static const std::string kExpectedEgid{"5"};

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
      { "auid", kExpectedAuid },
      { "uid", kExpectedUid },
      { "gid", kExpectedGid },
      { "euid", kExpectedEuid },
      { "suid", "1000" },
      { "fsuid", "1000" },
      { "egid", kExpectedEgid },
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
        REQUIRE(data.auid == std::strtoll(kExpectedAuid.c_str(), nullptr, 10));
        REQUIRE(data.uid == std::strtoll(kExpectedUid.c_str(), nullptr, 10));
        REQUIRE(data.gid == std::strtoll(kExpectedGid.c_str(), nullptr, 10));
        REQUIRE(data.euid == std::strtoll(kExpectedEuid.c_str(), nullptr, 10));
        REQUIRE(data.egid == std::strtoll(kExpectedEgid.c_str(), nullptr, 10));
        REQUIRE(data.succeeded);
      }
    }
  }

  GIVEN("a list of AUDIT_EXECVE records with split arguments") {
    // clang-format off
    static const MockedAuparseInterface::FieldList kAuditExecveRecord01 = {
      { "type", "1309" },
      { "argc", "4" },
      { "a0", "\"arg_0\"" }
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
      { "a2", "6172675F32" },
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
      auto status = AudispConsumer::processExecveRecords(execve_record,
                                                         raw_execve_record);

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

  GIVEN("a valid AUDIT_CWD record") {
    static const std::string kCwdFolderPath{"/path/to/folder"};

    // clang-format off
    static const MockedAuparseInterface::FieldList kAuditCwdRecord = {
      { "type", "1307" },
      { "cwd", kCwdFolderPath }
    };
    // clang-format on

    MockedAuparseInterface::Ref auparse;
    auto status = MockedAuparseInterface::create(auparse, kAuditCwdRecord);
    REQUIRE(status.succeeded());

    WHEN("parsing the event record") {
      std::string cwd_data;
      status = AudispConsumer::parseCwdRecord(cwd_data, auparse);

      REQUIRE(status.succeeded());

      THEN("record data is captured correctly") {
        REQUIRE(cwd_data == kCwdFolderPath);
      }
    }
  }

  GIVEN("a valid pair of AUDIT_PATH records") {
    static const std::string kFolderPath01{"/path/to/folder1"};
    static const std::string kFolderPathMode01{"0100644"};
    static const std::string kFolderPathOuid01{"111"};
    static const std::string kFolderPathOgid01{"222"};

    static const std::string kFolderPath02{"/path/to/folder2"};
    static const std::string kFolderPathMode02{"0100755"};
    static const std::string kFolderPathOuid02{"333"};
    static const std::string kFolderPathOgid02{"444"};

    // clang-format off
    static const MockedAuparseInterface::FieldList kAuditRecord01 = {
      { "type", "1302"},
      { "item", "0" },
      { "name", kFolderPath01 },
      { "inode", "5930" },
      { "dev", "00:18" },
      { "mode", kFolderPathMode01 },
      { "ouid", kFolderPathOuid01 },
      { "ogid", kFolderPathOgid01 },
      { "rdev", "00:00" },
      { "nametype", "NORMAL" },
      { "cap_fp", "0000000000000000" },
      { "cap_fi", "0000000000000000" },
      { "cap_fe", "0" },
      { "cap_fver", "0" }
    };
    // clang-format on

    // clang-format off
    static const MockedAuparseInterface::FieldList kAuditRecord02 = {
      { "type", "1302"},
      { "item", "1" },
      { "name", kFolderPath02 },
      { "inode", "6763" },
      { "dev", "00:18" },
      { "mode", kFolderPathMode02 },
      { "ouid", kFolderPathOuid02 },
      { "ogid", kFolderPathOgid02 },
      { "rdev", "00:00" },
      { "nametype", "NORMAL" },
      { "cap_fp", "0000000000000000" },
      { "cap_fi", "0000000000000000" },
      { "cap_fe", "0" },
      { "cap_fver", "0" }
    };
    // clang-format on

    // clang-format off
    static const std::vector<MockedAuparseInterface::FieldList> kAuditPathRecordList = {
      kAuditRecord01,
      kAuditRecord02
    };
    // clang-format on

    WHEN("parsing the event record") {
      AudispConsumer::PathRecordData path_data = {{"dummy_path", 100}};

      for (const auto &mocked_record : kAuditPathRecordList) {
        MockedAuparseInterface::Ref auparse;
        auto status = MockedAuparseInterface::create(auparse, mocked_record);
        REQUIRE(status.succeeded());

        status = AudispConsumer::parsePathRecord(path_data, auparse);
        REQUIRE(status.succeeded());
      }

      THEN("record data is captured correctly") {
        REQUIRE(path_data.size() == 2U);

        REQUIRE(path_data.at(0U).path == kFolderPath01);
        REQUIRE(path_data.at(0U).mode ==
                std::strtoll(kFolderPathMode01.c_str(), nullptr, 8));

        REQUIRE(path_data.at(0U).ouid ==
                std::strtoll(kFolderPathOuid01.c_str(), nullptr, 10));

        REQUIRE(path_data.at(0U).ogid ==
                std::strtoll(kFolderPathOgid01.c_str(), nullptr, 10));

        REQUIRE(path_data.at(1U).path == kFolderPath02);
        REQUIRE(path_data.at(1U).mode ==
                std::strtoll(kFolderPathMode02.c_str(), nullptr, 8));

        REQUIRE(path_data.at(1U).ouid ==
                std::strtoll(kFolderPathOuid02.c_str(), nullptr, 10));

        REQUIRE(path_data.at(1U).ogid ==
                std::strtoll(kFolderPathOgid02.c_str(), nullptr, 10));
      }
    }
  }
}
} // namespace zeek
