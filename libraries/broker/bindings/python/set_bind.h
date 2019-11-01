//
// Augment pybind11's {map,vector}_bind() with set_bind() for mapping std::set to Python's sets.
//
// This code is copied and adapted from pybind11's version for vector.
//

#include <pybind11/stl_bind.h>

NAMESPACE_BEGIN(pybind11)
NAMESPACE_BEGIN(detail)

/* For a set data structure, recursively check the value type (which is std::pair for maps) */
template <typename T>
struct is_comparable<T, enable_if_t<container_traits<T>::is_set>> {
    static constexpr const bool value =
        is_comparable<typename T::value_type>::value;
};

/* Fallback functions */
template <typename, typename, typename... Args> void set_if_copy_constructible(const Args &...) { }
template <typename, typename, typename... Args> void set_if_equal_operator(const Args &...) { }
template <typename, typename, typename... Args> void set_if_insertion_operator(const Args &...) { }
template <typename, typename, typename... Args> void set_modifiers(const Args &...) { }

template<typename Set, typename Class_>
void set_if_copy_constructible(enable_if_t<
    std::is_copy_constructible<Set>::value &&
    std::is_copy_constructible<typename Set::value_type>::value, Class_> &cl) {

    cl.def(init<const Set &>(), "Copy constructor");
}

template<typename Set, typename Class_>
void set_if_equal_operator(enable_if_t<is_comparable<Set>::value, Class_> &cl) {
    cl.def(self == self);
    cl.def(self != self);
}

// Set modifiers -- requires a copyable set_type:
template <typename Set, typename Class_>
void set_modifiers(enable_if_t<std::is_copy_constructible<typename Set::value_type>::value, Class_> &cl) {
    using T = typename Set::value_type;

    cl.def(init([](iterable it) {
        Set rval;
        for (handle h : it)
            rval.insert(h.cast<T>());
        return rval;
        }));

    cl.def("add",
        [](Set &s, const T &x) {
            s.insert(x);
        },
       arg("x"),
       "Insert an item into this set."
    );

    cl.def("remove",
        [](Set &s, const T &x) {
            s.erase(x);
        },
       arg("x"),
       "Removes an item from this set."
    );

    cl.def("clear",
        [](Set &s) {
            s.clear();
        },
       "Empties this set."
    );
}

// To iterate by copying objects, as std::set iterators are const.
template <typename Set, typename Class_>
void set_accessor(Class_ &cl) {
    using T = typename Set::value_type;
    using ItType   = typename Set::iterator;

    cl.def("__iter__",
           [](Set &s) {
               return make_iterator<
                   return_value_policy::copy, ItType, ItType, T>(
                   s.begin(), s.end());
           },
           keep_alive<0, 1>() /* Essential: keep list alive while iterator exists */
    );
}

template <typename Set, typename Class_> auto set_if_insertion_operator(Class_ &cl, std::string const &name)
    -> decltype(std::declval<std::ostream&>() << std::declval<typename Set::value_type>(), void()) {
  cl.def("__repr__",
         [name](Set& s) {
           std::ostringstream t;
           bool first = true;
           t << name << "{";
           for (auto i : s) {
             if (! first)
               t << ", ";
             t << i;
	     first = false;
           }
           t << '}';
           return t.str();
         },
         "Return the canonical string representation of this set.");
}

NAMESPACE_END(detail)

//
// std::set
//
template <typename Set, typename holder_type = std::unique_ptr<Set>, typename... Args>
class_<Set, holder_type> bind_set(module &m, std::string const &name, Args&&... args) {
    using Class_ = class_<Set, holder_type>;

    Class_ cl(m, name.c_str(), std::forward<Args>(args)...);

    cl.def(init<>());

    // Register copy constructor (if possible)
    detail::set_if_copy_constructible<Set, Class_>(cl);

    // Register comparison-related operators and functions (if possible)
    detail::set_if_equal_operator<Set, Class_>(cl);

    // Register stream insertion operator (if possible)
    detail::set_if_insertion_operator<Set, Class_>(cl, name);

    // Modifiers require copyable set value type
    detail::set_modifiers<Set, Class_>(cl);

    // Accessor and iterator; return by value if copyable, otherwise we return by ref + keep-alive
    detail::set_accessor<Set, Class_>(cl);

    cl.def("__bool__",
        [](const Set &s) -> bool {
            return !s.empty();
        },
        "Check whether the set is nonempty"
    );

    cl.def("__len__", &Set::size);

    return cl;
}

NAMESPACE_END(pybind11)
