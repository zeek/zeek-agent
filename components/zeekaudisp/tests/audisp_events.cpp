#include "audispconsumer.h"
#include "mockedaudispproducer.h"

#include <catch2/catch.hpp>

namespace zeek {
SCENARIO("AudispConsumer event parsers", "[AudispConsumer]") {
  GIVEN("a full execve event") {
    // clang-format off
    static const std::string kExecveEvent = "type=SYSCALL msg=audit(1572891138.674:28907): arch=c000003e syscall=59 success=yes exit=0 a0=7ffddc903cc0 a1=7f4e2c51a940 a2=55989bc751c0 a3=8 items=2 ppid=11413 pid=11414 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts1 ses=4294967295 comm=\"cat\" exe=\"/bin/cat\" key=(null)\ntype=EXECVE msg=audit(1572891138.674:28907): argc=2 a0=\"cat\" a1=\"--version\"\ntype=CWD msg=audit(1572891138.674:28907): cwd=\"/var/log/audit\"\ntype=PATH msg=audit(1572891138.674:28907): item=0 name=\"/bin/cat\" inode=5689 dev=00:18 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\ntype=PATH msg=audit(1572891138.674:28907): item=1 name=\"/lib64/ld-linux-x86-64.so.2\" inode=6763 dev=00:18 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0000000000000000 cap_fi=0000000000000000 cap_fe=0 cap_fver=0\ntype=PROCTITLE msg=audit(1572891138.674:28907): proctitle=636174002D2D76657273696F6E\n";
    // clang-format on

    IAudispConsumer::Ref audisp_consumer;

    {
      IAudispProducer::Ref audisp_producer;
      auto status = MockedAudispProducer::create(audisp_producer, kExecveEvent);
      REQUIRE(status.succeeded());

      status = AudispConsumer::createWithProducer(audisp_consumer,
                                                  std::move(audisp_producer));
      audisp_producer = {};

      REQUIRE(status.succeeded());
    }

    WHEN("processing the event records") {
      auto status = audisp_consumer->processEvents();
      REQUIRE(status.succeeded());

      THEN("record data is captured correctly") {
        AudispConsumer::AuditEventList event_list;
        status = audisp_consumer->getEvents(event_list);
        REQUIRE(status.succeeded());

        REQUIRE(event_list.size() == 1U);
      }
    }
  }
}
} // namespace zeek
