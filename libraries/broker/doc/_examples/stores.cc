#include <iostream>
#include <assert.h>
#include <poll.h>
#include <broker/broker.hh>

using namespace broker;

int main(){}

void f1() {

// --attach-master-start
  endpoint ep;
  auto ds = ep.attach_master("foo", memory);
// --attach-master-end

// --get-with-error-start
auto result = ds->get("foo");
if (result)
    std::cout << *result << std::endl; // Print current value of 'foo'.
else if (result.error() == ec::no_such_key)
    std::cout << "key 'foo' does not exist'" << std::endl;
else if (result.error() == ec::backend_failure)
    std::cout << "something went wrong with the backend" << std::endl;
else
    std::cout << "could not retrieve value at key 'foo'" << std::endl;
// --get-with-error-end

///

// --proxy-start
// Add a value to a data store (master or clone).
ds->put("foo", 42);
// Create a proxy.
auto proxy = store::proxy{*ds};
// Perform an asynchyronous request to look up a value.
auto id = proxy.get("foo");
// Get a file descriptor for event loops.
auto fd = proxy.mailbox().descriptor();
// Wait for result.
::pollfd p = {fd, POLLIN, 0};
auto n = ::poll(&p, 1, -1);
if (n < 0)
    std::terminate(); // poll failed

if (n == 1 && p.revents & POLLIN) {
    auto response = proxy.receive(); // Retrieve result, won't block now.
    assert(response.id == id);
    // Check whether we got data or an error.
    if (response.answer)
        std::cout << *response.answer << std::endl; // may print 42
    else if (response.answer.error() == ec::no_such_key)
        std::cout << "no such key: 'foo'" << std::endl;
    else
        std::cout << "failed to retrieve value at key 'foo'" << std::endl;
}
// --proxy-end


}


