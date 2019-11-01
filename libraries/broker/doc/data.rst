.. _data-model:

Data Model
==========

Broker offers a data model that is rich in types, closely modeled after `Zeek
<https://www.zeek.org>`_. Both :ref:`endpoints <communication>` and :ref:`data
stores <data-stores>` operate with the ``data`` abstraction as basic building
block, which is a type-erased variant structure that can hold many different
values.

There exists a total ordering on ``data``, induced first by the type
discriminator and then its value domain. For a example, an ``integer``
will always be smaller than a ``count``. While a meaningful ordering
exists only when comparing two values of the same type, the total
ordering makes it possible to use ``data`` as index in associative
containers.

Types
*****

None
----

The ``none`` type has exactly one value: ``nil``. A default-construct instance
of ``data`` is of type ``none``. One can use this value to represent optional
or invalid data.

Arithmetic
----------

The following types have arithmetic behavior.

Boolean
~~~~~~~

The type ``boolean`` can take on exactly two values: ``true`` and ``false``.
A ``boolean`` is a type alias for ``bool``.

Count
~~~~~

A ``count`` is a 64-bit *unsigned* integer and type alias for ``uint64_t``.

Integer
~~~~~~~

An ``integer`` is a 64-bit *signed* integer and type alias for ``int64_t``.

Real
~~~~

A ``real`` is a IEEE 754 double-precision floating point value, also commonly
known as ``double``.

Time
----

Broker offers two data types for expressing time: ``timespan`` and
``timestamp``.

Both types seamlessly interoperate with the C++ standard library time
facilities. In fact, they are concrete specializations of the time types in
|std_chrono|_:

.. code-block:: cpp

    using clock = std::chrono::system_clock;
    using timespan = std::chrono::duration<int64_t, std::nano>;
    using timestamp = std::chrono::time_point<clock, timespan>;

.. |std_chrono| replace:: ``std::chrono``
.. _std_chrono: http://en.cppreference.com/w/cpp/chrono

Timespan
~~~~~~~~

A ``timespan`` represents relative time duration in nanoseconds. Given that
the internal representation is a 64-bit signed integer, this allows for
representing approximately 292 years.

Timestamp
~~~~~~~~~

A ``timestamp`` represents an absolute point in time. The frame of reference
for a ``timestamp`` is the UNIX epoch, January 1, 1970. That is, a
``timestamp`` is simply an anchored ``timespan``. The function ``now()``
returns the current wallclock time as a ``timestamp``.

String
------

Broker directly supports |std_string|_ as one possible type of ``data``.

.. |std_string| replace:: ``std::string``
.. _std_string: http://en.cppreference.com/w/cpp/string/basic_string

Enum Value
~~~~~~~~~~

An ``enum_value`` wraps enum types defined by Zeek by storing the enum
value's name as a ``std::string``.  The receiver is responsible for
knowing how to map the name to the actual numeric value if it needs
that information.

Networking
----------

Broker comes with a few custom types from the networking domain.

Address
~~~~~~~

The type ``address`` is an IP address, which holds either an IPv4 or IPv6
address. One can construct an address from a byte sequence, along with
specifying the byte order and address family. An ``address`` can be masked by
zeroing a given number of bottom bits.

Subnet
~~~~~~

A ``subnet`` represents an IP prefix in `CIDR notation
<https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#CIDR_notation>`_.
It consists of two components: a network address and a prefix length.

Port
~~~~

A ``port`` represents a transport-level port number. Besides TCP and UDP ports,
there is a concept of an ICMP "port" where the source port is the ICMP message
type and the destination port the ICMP message code.

.. A ``port`` is rendered as a ``count`` followed by a ``/`` and then one of
.. ``tcp``, ``udp``, ``icmp``, or ``?``.

Containers
----------

Broker features the following container types: ``vector``, ``set``, and
``table``.

Vector
~~~~~~

A ``vector`` is a sequence of ``data``.

It is a type alias for ``std::vector<data>``.

Set
~~~

A ``set`` is a mathematical set with elements of type ``data``. A fixed ``data``
value can occur at most once in a ``set``.

It is a type alias for ``std::set<data>``.

Table
~~~~~

A ``set`` is an associative array with keys and values of type ``data``. That
is, it maps ``data`` to ``data``.

It is a type alias for ``std::map<data, data>``.

Interface
*********

The ``data`` abstraction offers two ways of interacting with the contained type
instance:

1. Querying a specific type ``T``. Similar to C++17's ``std::variant``, the function
   ``get_if<T>`` returns either a ``T*`` if the contained type is ``T`` and
   ``nullptr`` otherwise:

   .. code-block:: cpp

     auto x = data{...};
     if (auto i = get_if<integer>(x))
       f(*i); // safe use of x

   Alternatively, the function ``get<T>`` returns a reference of type
   ``T&`` or ``const T&``, based on whether the given ``data``
   argument is const-qualified:

   .. code-block:: cpp

     auto x = data{...};
     auto& str = get<std::string>(x); // throws std::bad_cast on type clash
     f(str); // safe use of x

2. Applying a *visitor*. Since ``data`` is a variant type, one can apply a
   visitor to it, i.e., dispatch a function call based on the type discriminator
   to the active type. A visitor is a polymorphic function object with
   overloaded ``operator()`` and a ``result_type`` type alias:

   .. code-block:: cpp

      struct visitor {
        using result_type = void;

        template <class T>
        result_type operator()(const T&) const {
          std::cout << ":-(" << std::endl;
        }

        result_type operator()(real r) const {
          std::cout << i << std::endl;
        }

        result_type operator()(integer i) const {
          std::cout << i << std::endl;
        }
      };

      auto x = data{42};
      visit(visitor{}, x); // prints 42
      x = 4.2;
      visit(visitor{}, x); // prints 4.2
      x = "42";
      visit(visitor{}, x); // prints :-(
