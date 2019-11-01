.. _communication:

Communication
=============

Broker's primary objective is to facilitate efficient communication through a
publish/subscribe model. In this model, entities send data by publishing to a
specific topic, and receive data by subscribing to topics of interest. The
asynchronous nature of publish/subscribe makes it a popular choice for loosely
coupled, distributed systems.

Broker is the successor of Broccoli.  Broker enables arbitrary
applications to communicate in Zeek's data model. In this chapter, we
first describe generic Broker communication between peers that don't
assume any specific message layout. Afterwards, we show how to exchange
events with Zeek through an additional Zeek-specific shim on top of
Broker's generic messages.

Exchanging Broker Messages
--------------------------

We start with a discussion of generic message exchange between Broker
clients. At the Broker level, messages are just arbitrary values
that have no further semantics attached. It's up to senders and
receivers to agree on a specific layout of messages (e.g., a set of
doubles for a measurement series).

Endpoints
~~~~~~~~~

Broker encapsulates its entire peering setup in an ``endpoint``
object. Multiple instances of an ``endpoint`` can exist in the same
process, but each ``endpoint`` features a thread-pool and
(configurable) scheduler, which determines the execution of Broker's
components. Using a single ``endpoint`` per OS process guarantees the
most efficient usage of available hardware resources. Nonetheless,
multiple Broker applications can seamlessly operate when linked
together, as there exists no global library state.

.. note::

  Instances of type ``endpoint`` have reference semantics: that is, they behave
  like a reference in that it's impossible to obtain an invalid one (unlike a
  null pointer). An ``endpoint`` can also be copied around cheaply, but is not
  safe against access from concurrent threads.

Peerings
~~~~~~~~

In order to publish or receive messages an endpoint needs to peer with other
endpoints. A peering is a bidirectional relationship between two
endpoints. Peering endpoints exchange subscriptions and then forward
messages accordingly. This allows for creating flexible communication
topologies that use topic-based message routing.

An endpoint can either initiate a peering itself by connecting to
remote locations, or wait for an incoming request:

.. literalinclude:: _examples/comm.cc
   :start-after: --peering-start
   :end-before: --peering-end

Sending Data
~~~~~~~~~~~~

In Broker a message consists of a *topic*-*data* pair. That is, endpoints
*publish* values as `data` instances along with a *topic* that steers
them to interested subscribers:

.. literalinclude:: _examples/comm.cc
   :start-after: --publish-start
   :end-before: --publish-end

.. note::

  Publishing a message can be a no-op if there exists no subscriber. Because
  Broker has fire-and-forget messaging semantics, the runtime does not generate
  a notification if no subscribers exist.

One can also explicitly create a dedicated ``publisher`` for a
specific topic first, and then use that to send subsequent messages.
This approach is better suited for high-volume streams, as it leverages
CAF's demand management internally:

.. literalinclude:: _examples/comm.cc
   :start-after: --publisher-start
   :end-before: --publisher-end

Finally, there's also a streaming version of the publisher that pulls
messages from a producer as capacity becomes available on the output
channel; see ``endpoint::publish_all`` and
``endpoint::publish_all_no_sync``.

See :ref:`data-model` for a detailed discussion on how to construct
values for messages in the form of various types of ``data`` instances.

Receiving Data
~~~~~~~~~~~~~~

Endpoints receive data by creating a ``subscriber`` attached to the
topics of interest. Subscriptions are prefix-based, matching all
topics that start with a given string. A ``subscriber`` can either
retrieve incoming messages explicitly by calling ``get`` or ``poll``
(synchronous API), or spawn a background worker to process messages
as they come in (asynchronous API).

Synchronous API
***************
    
The synchronous API exists for applications that want to poll for
messages explicitly. Once a subscriber is registered for topics,
calling ``get`` will wait for a new message:

.. literalinclude:: _examples/comm.cc
   :start-after: --get-start
   :end-before: --get-end

By default the function ``get`` blocks until the subscriber has at
least one message available, which it then returns. Each retrieved
message consists of the same two elements that the publisher passed
along: the topic that the message has been published to, and the
message's payload in the form of an arbitray Broker value, (i.e., a
`data` instance). The example just prints them both out.

Blocking indefinitely until messages arrive often won't work well, in
particular not in combination with existing event loops or polling.
Therefore, ``get`` takes an additional optional timeout parameter to wait
only for a certain amount of time. Alternatively, one can also use
``available`` to explicitly check for available messages, or ``poll``
to extract just all currently pending messages (which may be none):

.. literalinclude:: _examples/comm.cc
   :start-after: --poll-start
   :end-before: --poll-end

For integration into event loops, ``subscriber`` also provides a file
descriptor that signals whether messages are available:

.. literalinclude:: _examples/comm.cc
   :start-after: --fd-start
   :end-before: --fd-end

Asynchronous API
****************

TODO: Document.

.. todo: Add docs for asynchronous API.

.. If your application does not require a blocking API, the non-blocking API
.. offers an asynchronous alternative. Unlike the blocking API, non-blocking
.. endpoints take a callback for each topic they subscribe to:
.. 
.. .. code-block:: cpp
.. 
..   context ctx;
..   auto ep = ctx.spawn<nonblocking>();
..   ep.subscribe("/foo", [=](const topic& t, const data& d) {
..     std::cout << t << " -> " << d << std::endl;
..   });
..   ep.subscribe("/bar", [=](const topic& t, const data& d) {
..     std::cout << t << " -> " << d << std::endl;
..   });
.. 
.. When a new message matching the subscription arrives, Broker dispatches it to
.. the callback without blocking.
.. 
.. .. warning::
.. 
..   The function ``subscribe`` returns immediately. Capturing variable *by
..   reference* introduces a dangling reference once the outer frame returns.
..   Therefore, only capture locals *by value*.

.. _status-error-messages:

Status and Error Messages
~~~~~~~~~~~~~~~~~~~~~~~~~

Broker informs clients about any communication errors---and optionally
also about non-critical connectivity changes---through separate
``status`` messages.  To get access to that information, one creates a
``status_subscriber``, which provides a similar synchronous
``get/available/poll`` API as the standard message subscriber. By
default, a ``status_subscriber`` returns only errors:


.. literalinclude:: _examples/comm.cc
   :start-after: --status-subscriber-err-start
   :end-before: --status-subscriber-err-end

Errors reflect failures that may impact the correctness of operation.
``err.code()`` returns an enum ``ec`` that codifies existing error
codes:

.. literalinclude:: ../broker/error.hh
   :language: cpp
   :lines: 23-51

To receive non-critical status messages as well, specify that when
creating the ``status_subscriber``:

.. literalinclude:: _examples/comm.cc
   :start-after: --status-subscriber-all-start
   :end-before: --status-subscriber-all-end

Status messages represent non-critical changes to the topology. For
example, after a successful peering, both endpoints receive a
``peer_added`` status message. The concrete semantics of a status
depend on its embedded code, which the enum ``sc`` codifies:

.. literalinclude:: ../broker/status.hh
   :language: cpp
   :lines: 26-35

Status messages have an optional *context* and an optional descriptive
*message*. The member function ``context<T>`` returns a ``const T*``
if the context is available. The type of available context information
is dependent on the status code enum ``sc``. For example, all
``sc::peer_*`` status codes include an ``endpoint_info`` context as
well as a message.

Forwarding
----------

In topologies where multiple endpoints are connected, an endpoint
forwards incoming messages to peers by default for topics that it is
itself subscribed to. One can configure additional topics to forward,
independent of the local subscription status, through the method
``endpoint::forward(std::vector<topics>)``. One can also disable
forwarding of remote messages altogether through the Broker
configuration option ``forward`` when creating an endpoint.

When forwarding messages Broker assumes all connected endpoints
form a tree topology without any loops. Still, to avoid messages
circling indefinitely if a loop happens accidentally, Broker's message
forwarding adds a TTL value to messages, and drops any that have
traversed that many hops. The default TTL is 20; it can be changed by
setting the Broker configuration option ``ttl``. Note that it is the
first hop's TTL configuration that determines a message's lifetime
(not the original sender's).

.. _zeek_events_cpp:

Exchanging Zeek Events
----------------------

The communication model discussed so far remains generic for all
Broker clients in that it doesn't associate any semantics with the
values exchanged through messages. In practice, however, senders and
receivers will need to agree on a specific data layout for the values
exchanged, so that they interpret them in the same way. This is in
particular true for exchanging events with Zeek---which is one of the
main applications for Broker in the first place. To support that,
Broker provides built-in support for sending and receiving Zeek events
through a small Zeek-specific shim on top of the generic message model.
The shim encapsulates Zeek events and takes care of converting them
into the expected lower-level message layout that gets transmitted.
This way, Zeek events can be exchanged between an external
Broker client and Zeek itself---and also even just between Broker
clients without any Zeek instances at all.

Here's a complete ping/ping example between a C++ Broker client and
Zeek:

.. literalinclude:: _examples/ping.zeek

.. literalinclude:: _examples/ping.cc

.. code-block:: bash

    # g++ -std=c++11 -lbroker -lcaf_core -lcaf_io -lcaf_openssl -o ping ping.cc
    # zeek ping.zeek &
    # ./ping
    received pong[0]
    received pong[1]
    received pong[2]
    received pong[3]
    received pong[4]
