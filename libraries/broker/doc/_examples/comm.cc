#include <iostream>
#include <poll.h>
#include <broker/broker.hh>

using namespace broker;

int main(){}

void f1() {

// --get-start
endpoint ep;
auto sub = ep.make_subscriber({"/topic/test"});
auto msg = sub.get();
auto topic = get_topic(msg);
auto data_ = get_data(msg);
std::cout << "topic: " << topic << " data: " << data_ << std::endl;
// --get-end

///

// --poll-start
if ( sub.available() )
    msg = sub.get(); // Won't block now.

for ( auto m : sub.poll() ) // Iterate over all available messages
    std::cout << "topic: " << get_topic(m) << " data: " << get_data(m) << std::endl;
// --poll-end

///

// --fd-start
auto fd = sub.fd();
::pollfd p = {fd, POLLIN, 0};
auto n = ::poll(&p, 1, -1);
if (n < 0)
    std::terminate(); // poll failed

if (n == 1 && p.revents & POLLIN) {
    auto msg = sub.get(); // Won't block now.
    // ...
    }
// --fd-end

///

// --publish-start
ep.publish("/topic/test", "42"); // Message is a single number.
ep.publish("/topic/test", vector{1, 2, 3}); // Message is a vector of values.
// --publish-end

///

// --publisher-start
auto pub = ep.make_publisher("/topic/test");
pub.publish("42"); // Message is a single number.
pub.publish(vector{1, 2, 3}); // Message is a vector.
// --publisher-end

///

// --peering-start
// Open port and subscribe to 'foo' with all
// incoming peerings.
// Establish outgoing peering and subscribe to 'bar'.
endpoint ep1;
auto sub1 = ep1.make_subscriber({"/topic/test"});
ep1.peer("127.0.0.1", 9999);

endpoint ep0;
auto sub0 = ep0.make_subscriber({"/topic/test"});
ep0.listen("127.0.0.1", 9999);
// --peering-end

// --status-subscriber-err-start
auto ss = ep.make_status_subscriber();

if ( ss.available() ) {
    auto ss_res = ss.get();
    auto err = caf::get<error>(ss_res); // Won't block now.
    std::cerr << "Broker error:" << err.code() << ", " << to_string(err) << std::endl;
}
// --status-subscriber-err-end
}

void f2()
{
endpoint ep;

// --status-subscriber-all-start
auto ss = ep.make_status_subscriber(true); // Get status updates and errors.

if ( ss.available() ) {
    auto s = ss.get();

    if ( auto err = caf::get_if<error>(&s) )
        std::cerr << "Broker error:" << err->code() << ", " << to_string(*err) << std::endl;

    if ( auto st = caf::get_if<status>(&s) ) {
	if ( auto ctx = st->context<endpoint_info>() ) // Get the peer this is about if available.
           std::cerr << "Broker status update regarding "
	             << ctx->network->address
	             << ":" << to_string(*st) << std::endl;
	else
           std::cerr << "Broker status update:"
	             << to_string(*st) << std::endl;
    }
// --status-subscriber-all-end
}

}


