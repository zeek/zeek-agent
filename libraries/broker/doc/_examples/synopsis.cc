#include <iostream>
#include <broker/broker.hh>

using namespace broker;

int main()
{
    endpoint ep;
    ep.peer("1.2.3.4", 9999); // Connect to remote endpoint on given address/port.

    // Messages

    ep.publish("/test/t1", set{1, 2, 3}); // Publish data under a given topic.

    auto sub = ep.make_subscriber({"/test/t2"}); // Subscribe to incoming messages for topic.
    auto msg = sub.get(); // Wait for one incoming message.
    std::cout << "got data for topic " << get_topic(msg) << ": " << get_data(msg) << std::endl;

    // Data stores

    auto m = ep.attach_master("yoda", backend::memory); // Create data store.

    m->put(4.2, -42); // Write into store.
    m->put("bar", vector{true, 7u, now()});

    if ( auto d = m->get(4.2) ) // Look up in store.
        std::cout << "value of 4.2 is " << d << std::endl;
    else
        std::cout << "no such key: 4.2" << std::endl;
}


