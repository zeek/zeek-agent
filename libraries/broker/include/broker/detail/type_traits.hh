#pragma once

#include <cstddef>

#include <type_traits>

#include <caf/detail/type_traits.hpp>

namespace broker {

class data;
class status;
class topic;

namespace detail {

// std::enable_if_t shortcut from C++14.
template <bool B, class T = void>
using enable_if_t = typename std::enable_if<B, T>::type;

// std::conditional_t shortcut from C++14.
template <bool B, class T, class F>
using conditional_t = typename std::conditional<B, T, F>::type;

// std::conjunction from C++17.
template <class...>
struct conjunction : std::true_type {};

template <class B1>
struct conjunction<B1> : B1 { };

template <class B1, class... Bn>
struct conjunction<B1, Bn...>
  : conditional_t<B1::value != false, conjunction<Bn...>, B1>  {};

// std::remove_reference_t shortcut from C++14.
template <class T>
using remove_reference_t = typename std::remove_reference<T>::type;

// std::decay_t shortcut from C++14.
template <class T>
using decay_t = typename std::decay<T>::type;

// std::aligned_storage_t shortcut from C++14.
template <size_t Len, size_t Align>
using aligned_storage_t = typename std::aligned_storage<Len, Align>::type;

template <bool B, class T = void>
using disable_if = std::enable_if<!B, T>;

template <bool B, class T = void>
using disable_if_t = typename disable_if<B, T>::type;

template <class A, class B>
using is_same_or_derived = std::is_base_of<A, remove_reference_t<B>>;

template <class A, class B>
using disable_if_same_or_derived = disable_if<is_same_or_derived<A, B>::value>;

template <class A, class B>
using disable_if_same_or_derived_t =
  typename disable_if_same_or_derived<A, B>::type;

template <template <class> class F, class Head>
constexpr decltype(F<Head>::value) max() {
  return F<Head>::value;
}

template <template <class> class F, class Head, class Next, class... Tail>
constexpr decltype(F<Head>::value) max() {
  return max<F, Head>() > max<F, Next, Tail...>() ? max<F, Head>() :
                                                    max<F, Next, Tail...>();
}

// A variadic extension of std::is_same.
template <class... Ts> struct are_same;

template <>
struct are_same<> : std::true_type {};

template <class T>
struct are_same<T> : std::true_type {};

template <class T0, class T1, class... Ts>
struct are_same<T0, T1, Ts...> :
  conditional_t<
    std::is_same<T0, T1>::value,
    are_same<T1, Ts...>,
    std::false_type
  > {};

// Trait that checks for an overload of convert(const From&, T&).
template <class From, class To>
struct can_convert {
  using from_type = decay_t<From>;
  using to_type = typename std::add_lvalue_reference<decay_t<To>>::type;

  template <class T>
  static auto test(T* x)
  -> decltype(convert(*x, std::declval<to_type>()), std::true_type());

  template <class T>
  static auto test(...) -> std::false_type;

  using type = decltype(test<from_type>(nullptr));
  static constexpr bool value = type::value;
};

// Traits to verify callback types.

template <
  class F,
  class T = caf::detail::get_callable_trait<F>,
  class A = typename T::arg_types
>
struct is_message_callback
  : conjunction<
      std::is_same<void, typename T::result_type>,
      std::integral_constant<bool, caf::detail::tl_size<A>::value == 2>,
      std::is_same<decay_t<typename caf::detail::tl_head<A>::type>, topic>,
      std::is_same<decay_t<typename caf::detail::tl_back<A>::type>, data>
    > {};

template <
  class F,
  class T = caf::detail::get_callable_trait<F>,
  class A = typename T::arg_types
>
struct is_status_callback
  : conjunction<
      std::is_same<void, typename T::result_type>,
      std::integral_constant<bool, caf::detail::tl_size<A>::value == 1>,
      std::is_same<decay_t<typename caf::detail::tl_head<A>::type>, status>
    > {};

// As above, but produces a much friendler compiler error message.

template <class Callback>
void verify_message_callback() {
  using callback_type = caf::detail::get_callable_trait<Callback>;
  using args = typename callback_type::arg_types;
  using first = typename caf::detail::tl_head<args>::type;
  using second = typename caf::detail::tl_back<args>::type;
  static_assert(std::is_same<void, typename callback_type::result_type>{},
                "data callback must not have a return value");
  static_assert(caf::detail::tl_size<args>::value == 2,
                "data callback must have two arguments");
  static_assert(std::is_same<detail::decay_t<first>, topic>::value,
                "first argument must be of type broker::topic");
  static_assert(std::is_same<detail::decay_t<second>, data>::value,
                "second argument must be of type broker::data");
}

template <class Callback>
void verify_status_callback() {
  using callback_type = caf::detail::get_callable_trait<Callback>;
  using args = typename callback_type::arg_types;
  using first = typename caf::detail::tl_head<args>::type;
  static_assert(std::is_same<void, typename callback_type::result_type>{},
                "status callback must not have a return value");
  static_assert(caf::detail::tl_size<args>::value == 1,
                "status callback can have only one argument");
  static_assert(std::is_same<detail::decay_t<first>, status>::value,
                "status callback must have broker::status as argument type");
}

} // namespace detail
} // namespace broker
