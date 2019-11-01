#define SUITE radix_tree

#include "broker/detail/radix_tree.hh"

#include "test.hh"

#include <deque>
#include <iterator>
#include <set>
#include <sstream>
#include <string>
#include <utility>

using namespace std;
using namespace broker;

using test_radix_tree = detail::radix_tree<int>;

namespace {

bool check_match(deque<test_radix_tree::iterator> matches,
                 std::set<pair<string, int>> expected) {
  if (matches.size() != expected.size())
    return false;
  for (auto it = expected.begin(); it != expected.end(); ++it) {
    auto i = distance(expected.begin(), it);
    if (matches[i]->first != it->first)
      return false;
    if (matches[i]->second != it->second)
      return false;
  }
  return true;
}

bool find(deque<test_radix_tree::iterator> haystack, pair<string, int> needle) {
  for (const auto& h : haystack)
    if (h->first == needle.first && h->second == needle.second)
      return true;
  return false;
}

unsigned char key1[300] = {
  16,  0,   0,   0,   7,   10,  0,   0,   0,   2,   17,  10,  0,   0,   0,
  120, 10,  0,   0,   0,   120, 10,  0,   0,   0,   216, 10,  0,   0,   0,
  202, 10,  0,   0,   0,   194, 10,  0,   0,   0,   224, 10,  0,   0,   0,
  230, 10,  0,   0,   0,   210, 10,  0,   0,   0,   206, 10,  0,   0,   0,
  208, 10,  0,   0,   0,   232, 10,  0,   0,   0,   124, 10,  0,   0,   0,
  124, 2,   16,  0,   0,   0,   2,   12,  185, 89,  44,  213, 251, 173, 202,
  211, 95,  185, 89,  110, 118, 251, 173, 202, 199, 101, 0,   8,   18,  182,
  92,  236, 147, 171, 101, 150, 195, 112, 185, 218, 108, 246, 139, 164, 234,
  195, 58,  177, 0,   8,   16,  0,   0,   0,   2,   12,  185, 89,  44,  213,
  251, 173, 202, 211, 95,  185, 89,  110, 118, 251, 173, 202, 199, 101, 0,
  8,   18,  180, 93,  46,  151, 9,   212, 190, 95,  102, 178, 217, 44,  178,
  235, 29,  190, 218, 8,   16,  0,   0,   0,   2,   12,  185, 89,  44,  213,
  251, 173, 202, 211, 95,  185, 89,  110, 118, 251, 173, 202, 199, 101, 0,
  8,   18,  180, 93,  46,  151, 9,   212, 190, 95,  102, 183, 219, 229, 214,
  59,  125, 182, 71,  108, 180, 220, 238, 150, 91,  117, 150, 201, 84,  183,
  128, 8,   16,  0,   0,   0,   2,   12,  185, 89,  44,  213, 251, 173, 202,
  211, 95,  185, 89,  110, 118, 251, 173, 202, 199, 101, 0,   8,   18,  180,
  93,  46,  151, 9,   212, 190, 95,  108, 176, 217, 47,  50,  219, 61,  134,
  207, 97,  151, 88,  237, 246, 208, 8,   18,  255, 255, 255, 219, 191, 198,
  134, 5,   223, 212, 72,  44,  208, 250, 180, 14,  1,   0,   0,   8,   '\0'};

unsigned char key2[303] = {
  16,  0,   0,   0,   7,   10,  0,   0,   0,   2,   17,  10,  0,   0,   0,
  120, 10,  0,   0,   0,   120, 10,  0,   0,   0,   216, 10,  0,   0,   0,
  202, 10,  0,   0,   0,   194, 10,  0,   0,   0,   224, 10,  0,   0,   0,
  230, 10,  0,   0,   0,   210, 10,  0,   0,   0,   206, 10,  0,   0,   0,
  208, 10,  0,   0,   0,   232, 10,  0,   0,   0,   124, 10,  0,   0,   0,
  124, 2,   16,  0,   0,   0,   2,   12,  185, 89,  44,  213, 251, 173, 202,
  211, 95,  185, 89,  110, 118, 251, 173, 202, 199, 101, 0,   8,   18,  182,
  92,  236, 147, 171, 101, 150, 195, 112, 185, 218, 108, 246, 139, 164, 234,
  195, 58,  177, 0,   8,   16,  0,   0,   0,   2,   12,  185, 89,  44,  213,
  251, 173, 202, 211, 95,  185, 89,  110, 118, 251, 173, 202, 199, 101, 0,
  8,   18,  180, 93,  46,  151, 9,   212, 190, 95,  102, 178, 217, 44,  178,
  235, 29,  190, 218, 8,   16,  0,   0,   0,   2,   12,  185, 89,  44,  213,
  251, 173, 202, 211, 95,  185, 89,  110, 118, 251, 173, 202, 199, 101, 0,
  8,   18,  180, 93,  46,  151, 9,   212, 190, 95,  102, 183, 219, 229, 214,
  59,  125, 182, 71,  108, 180, 220, 238, 150, 91,  117, 150, 201, 84,  183,
  128, 8,   16,  0,   0,   0,   3,   12,  185, 89,  44,  213, 251, 133, 178,
  195, 105, 183, 87,  237, 150, 155, 165, 150, 229, 97,  182, 0,   8,   18,
  161, 91,  239, 50,  10,  61,  150, 223, 114, 179, 217, 64,  8,   12,  186,
  219, 172, 150, 91,  53,  166, 221, 101, 178, 0,   8,   18,  255, 255, 255,
  219, 191, 198, 134, 5,   208, 212, 72,  44,  208, 250, 180, 14,  1,   0,
  0,   8,   '\0'};

} // namespace <anonymous>

TEST(very long insert) {
  detail::radix_tree<void*> rt;
  CHECK(rt.insert({string(key1, key1 + 299), key1}).second);
  CHECK(rt.insert({string(key2, key2 + 302), key2}).second);
  CHECK(!rt.insert({string(key2, key2 + 302), key2}).second);
  CHECK(rt.size() == 2);
}

TEST(long prefix) {
  test_radix_tree rt{
    {"this:key:has:a:long:prefix:3", 3},
    {"this:key:has:a:long:common:prefix:2", 2},
    {"this:key:has:a:long:common:prefix:1", 1},
  };
  const char* s;
  s = "this:key:has:a:long:common:prefix:1";
  CHECK(rt.find(s)->second == 1);
  s = "this:key:has:a:long:common:prefix:2";
  CHECK(rt.find(s)->second == 2);
  s = "this:key:has:a:long:prefix:3";
  CHECK(rt.find(s)->second == 3);
  CHECK(check_match(rt.prefixed_by("this:key:has"),
                    {make_pair("this:key:has:a:long:common:prefix:1", 1),
                     make_pair("this:key:has:a:long:common:prefix:2", 2),
                     make_pair("this:key:has:a:long:prefix:3", 3)}));
  CHECK(check_match(rt.prefix_of("this:key:has:a:long:prefix:321"),
                    {make_pair("this:key:has:a:long:prefix:3", 3)}));
  CHECK(rt.prefix_of("this:key:has:a:long:common:prefix:3").empty());
  CHECK(check_match(rt.prefix_of("this:key:has:a:long:common:prefix:1"),
                    {make_pair("this:key:has:a:long:common:prefix:1", 1)}));
  CHECK(check_match(rt.prefix_of("this:key:has:a:long:common:prefix:2"),
                    {make_pair("this:key:has:a:long:common:prefix:2", 2)}));
}

TEST(prefix_of) {
  test_radix_tree t{make_pair("one", 1)};

  CHECK(t.prefix_of("").empty());
  CHECK(t.prefix_of("nope").empty());
  CHECK(t.prefix_of("on").empty());
  CHECK(check_match(t.prefix_of("one"), {make_pair("one", 1)}));
  CHECK(check_match(t.prefix_of("one-hundred"), {make_pair("one", 1)}));
  t["one-hundred"] = 100;
  CHECK(t.prefix_of("").empty());
  CHECK(t.prefix_of("nope").empty());
  CHECK(t.prefix_of("on").empty());
  CHECK(check_match(t.prefix_of("one"), {make_pair("one", 1)}));
  CHECK(check_match(t.prefix_of("one-hundred"),
                    {make_pair("one", 1), make_pair("one-hundred", 100)}));
  t["one-hundred-thousand"] = 100000;
  CHECK(t.prefix_of("").empty());
  CHECK(t.prefix_of("nope").empty());
  CHECK(t.prefix_of("on").empty());
  CHECK(check_match(t.prefix_of("one"), {make_pair("one", 1)}));
  CHECK(check_match(t.prefix_of("one-hundred"),
                    {make_pair("one", 1), make_pair("one-hundred", 100)}));
  CHECK(check_match(t.prefix_of("one-hundred-thousand"),
                    {make_pair("one", 1), make_pair("one-hundred", 100),
                    make_pair("one-hundred-thousand", 100000)}));
  CHECK(check_match(t.prefix_of("one-hundred-two"),
                    {make_pair("one", 1), make_pair("one-hundred", 100)}));
  t["two"] = 2;
  CHECK(t.prefix_of("").empty());
  CHECK(t.prefix_of("nope").empty());
  CHECK(t.prefix_of("on").empty());
  CHECK(check_match(t.prefix_of("one"), {make_pair("one", 1)}));
  CHECK(check_match(t.prefix_of("one-hundred"),
                    {make_pair("one", 1), make_pair("one-hundred", 100)}));
  CHECK(check_match(t.prefix_of("one-hundred-thousand"),
                    {make_pair("one", 1), make_pair("one-hundred", 100),
                    make_pair("one-hundred-thousand", 100000)}));
  CHECK(check_match(t.prefix_of("one-hundred-two"),
                    {make_pair("one", 1), make_pair("one-hundred", 100)}));
  t["two-fifty"] = 250;
  CHECK(t.prefix_of("").empty());
  CHECK(t.prefix_of("nope").empty());
  CHECK(t.prefix_of("on").empty());
  CHECK(check_match(t.prefix_of("one"), {make_pair("one", 1)}));
  CHECK(check_match(t.prefix_of("one-hundred"),
                    {make_pair("one", 1), make_pair("one-hundred", 100)}));
  CHECK(check_match(t.prefix_of("one-hundred-thousand"),
                    {make_pair("one", 1), make_pair("one-hundred", 100),
                    make_pair("one-hundred-thousand", 100000)}));
  CHECK(check_match(t.prefix_of("one-hundred-two"),
                    {make_pair("one", 1), make_pair("one-hundred", 100)}));
  CHECK(check_match(t.prefix_of("two-fifty-five"),
                    {make_pair("two", 2), make_pair("two-fifty", 250)}));
  t["zero"] = 0;
  CHECK(t.prefix_of("").empty());
  CHECK(t.prefix_of("nope").empty());
  CHECK(t.prefix_of("on").empty());

  CHECK(check_match(t.prefix_of("one"), {make_pair("one", 1)}));
  CHECK(check_match(t.prefix_of("one-hundred"),
                    {make_pair("one", 1), make_pair("one-hundred", 100)}));
  CHECK(check_match(t.prefix_of("one-hundred-thousand"),
                    {make_pair("one", 1), make_pair("one-hundred", 100),
                    make_pair("one-hundred-thousand", 100000)}));
  CHECK(check_match(t.prefix_of("one-hundred-two"),
                    {make_pair("one", 1), make_pair("one-hundred", 100)}));
  CHECK(check_match(t.prefix_of("two-fifty-five"),
                    {make_pair("two", 2), make_pair("two-fifty", 250)}));
  t[""] = -1;
  CHECK(check_match(t.prefix_of(""), {make_pair("", -1)}));
  CHECK(check_match(t.prefix_of("nope"), {make_pair("", -1)}));
  CHECK(check_match(t.prefix_of("on"), {make_pair("", -1)}));
  CHECK(check_match(t.prefix_of("one"),
                    {make_pair("", -1), make_pair("one", 1)}));
  CHECK(check_match(t.prefix_of("one-hundred"),
                    {make_pair("", -1), make_pair("one", 1),
                     make_pair("one-hundred", 100)}));
  CHECK(check_match(t.prefix_of("one-hundred-thousand"),
                    {make_pair("", -1), make_pair("one", 1),
                     make_pair("one-hundred", 100),
                     make_pair("one-hundred-thousand", 100000)}));
  CHECK(check_match(t.prefix_of("one-hundred-two"),
                    {make_pair("", -1), make_pair("one", 1),
                     make_pair("one-hundred", 100)}));
  CHECK(check_match(t.prefix_of("two-fifty-five"),
                    {make_pair("", -1), make_pair("two", 2),
                     make_pair("two-fifty", 250)}));
}

TEST(prefix match) {
  test_radix_tree t{
    {"api.foo.bar", 1}, {"api.foo.baz", 2}, {"api.foe.fum", 3},
    {"abc.123.456", 4}, {"api.foo", 5},     {"api", 6},
  };
  CHECK(check_match(t.prefixed_by("api"),
                    {make_pair("api", 6), make_pair("api.foe.fum", 3),
                    make_pair("api.foo", 5), make_pair("api.foo.bar", 1),
                    make_pair("api.foo.baz", 2)}));
  CHECK(check_match(t.prefixed_by("a"),
                    {make_pair("abc.123.456", 4), make_pair("api", 6),
                    make_pair("api.foe.fum", 3), make_pair("api.foo", 5),
                    make_pair("api.foo.bar", 1), make_pair("api.foo.baz", 2)
                    }));
  CHECK(t.prefixed_by("b").empty());
  CHECK(check_match(t.prefixed_by("api."),
                    {make_pair("api.foe.fum", 3), make_pair("api.foo", 5),
                     make_pair("api.foo.bar", 1), make_pair("api.foo.baz", 2),
                     }));
  CHECK(check_match(t.prefixed_by("api.foo.bar"),
                    {make_pair("api.foo.bar", 1)}));
  CHECK(t.prefixed_by("api.end").empty());
  CHECK(check_match(t.prefixed_by(""),
                    {make_pair("abc.123.456", 4), make_pair("api", 6),
                     make_pair("api.foe.fum", 3), make_pair("api.foo", 5),
                     make_pair("api.foo.bar", 1), make_pair("api.foo.baz", 2),
                     }));
  CHECK(check_match(t.prefix_of("api.foo.bar.baz"),
                    {make_pair("api", 6), make_pair("api.foo", 5),
                    make_pair("api.foo.bar", 1)}));
  CHECK(check_match(t.prefix_of("api.foo.fum"),
                    {make_pair("api", 6), make_pair("api.foo", 5)}));
  CHECK(t.prefix_of("").empty());
}

TEST(many keys) {
  test_radix_tree t;
  deque<string> keys;
  deque<int> values;
  for (int i = 0; i < 1000; ++i) {
    stringstream ss;
    ss << i;
    keys.push_back(ss.str());
    values.push_back(i);
    CHECK(t.insert(make_pair(keys[i], values[i])).second);
  }
  CHECK(t.size() == 1000);
  for (const auto& i : values)
    CHECK(t.find(keys[i])->second == i);
  auto matches = t.prefixed_by("1");
  CHECK(matches.size() == 1 + 10 + 100);
  for (const auto& p : matches)
    CHECK(p->first[0] == '1');
  matches = t.prefix_of("109876");
  CHECK(check_match(matches,
                    {make_pair("109", 109),
                     make_pair("10", 10),
                     make_pair("1", 1)}));
  matches = t.prefix_of("54321");
  CHECK(check_match(matches,
                    {make_pair("543", 543),
                    make_pair("54", 54),
                    make_pair("5", 5)}));
  for (int i = 0; i < 500; ++i) {
    CHECK(t.erase(keys[i]) == 1);
    CHECK(t.erase(keys[i]) == 0);
  }
  CHECK(t.size() == 500);
  for (const auto& i : values) {
    if (i < 500)
      CHECK(t.find(keys[i]) == t.end());
    else
      CHECK(t.find(keys[i])->second == i);
  }
  for (int i = 500; i < 995; ++i) {
    CHECK(t.erase(keys[i]) == 1);
    CHECK(t.erase(keys[i]) == 0);
  }
  for (const auto& i : values) {
    if (i < 995)
      CHECK(t.find(keys[i]) == t.end());
    else
      CHECK(t.find(keys[i])->second == i);
  }
  for (int i = 0; i < 1000; ++i) {
    if (i < 995)
      CHECK(t.insert(make_pair(keys[i], values[i])).second);
    else
      CHECK(!t.insert(make_pair(keys[i], values[i])).second);
  }
  CHECK(t.size() == 1000);
  matches = t.prefixed_by("9");
  CHECK(matches.size() == 1 + 10 + 100);
  for (const auto& p : matches)
    CHECK(p->first[0] == '9');
  matches = t.prefix_of("54321");
  CHECK(check_match(matches,
                    {make_pair("543", 543),
                     make_pair("54", 54),
                     make_pair("5", 5)}));
  t.clear();
  CHECK(t.size() == 0);
}

TEST(dense nodes) {
  test_radix_tree t;
  auto idx = 0;
  for (auto i = 0; i < 256; ++i)
    for (auto j = 0; j < 256; ++j)
      for (auto k = 0; k < 10; ++k) {
        stringstream ss;
        ss.put(i).put(j);
        ss << k;
        CHECK(t.insert(make_pair(ss.str(), idx)).second);
        ++idx;
      }
  CHECK(t.size() == 256 * 256 * 10);
  CHECK(t.prefixed_by("a").size() == 256 * 10);
  CHECK(t.prefix_of("ab0123").size() == 1);
  CHECK(t.find("az5")->second == 'a' * 256 * 10 + 'z' * 10 + 5);
  for (auto i = 0; i < 256; ++i)
    for (auto j = 0; j < 256; ++j)
      for (auto k = 0; k < 10; ++k) {
        stringstream ss;
        ss.put(i).put(j);
        ss << k;
        string s = ss.str();
        CHECK(t.find(s)->second == i * 256 * 10 + j * 10 + k);
        if (i == 'b' && j == 'r')
          continue;
        CHECK(t.erase(s));
      }
  CHECK(t.size() == 10);
  for (auto i = 0; i < 10; ++i) {
    stringstream ss;
    ss << "br" << i;
    CHECK(t.find(ss.str())->second == 'b' * 256 * 10 + 'r' * 10 + i);
  }
  CHECK(t.prefixed_by("b").size() == 10);
  CHECK(t.prefixed_by("br").size() == 10);
  CHECK(t.prefixed_by("br0").size() == 1);
  CHECK(t.prefix_of("br0").size() == 1);
}

TEST(general) {
  test_radix_tree tree;
  CHECK(tree.empty());
  tree["apache"] = 0;
  tree["afford"] = 1;
  tree["available"] = 2;
  tree["affair"] = 3;
  tree["avenger"] = 4;
  tree["binary"] = 5;
  tree["bind"] = 6;
  tree["brother"] = 7;
  tree["brace"] = 8;
  tree["blind"] = 9;
  /*
          (root)
       /          \
      a             b
     /|\          /   |
   ff | v       in     |\
  / |  |   \    /  \    |  r
  ord$ air$ |    \  ary$ d$  |   \
      |    |\         lind$ \
    pache$ | enger$         | \
           ailable$       ace$ other$
  */
  MESSAGE("copy construction");
  test_radix_tree copy(tree);
  test_radix_tree other_copy = tree;
  CHECK(tree.size() == 10);
  CHECK(copy.size() == 10);
  CHECK(other_copy.size() == 10);
  CHECK(tree == copy);
  CHECK(tree == other_copy);
  for (const auto& p : tree) {
    CHECK(copy.find(p.first) != tree.end());
    CHECK(other_copy.find(p.first) != tree.end());
  }
  CHECK(copy.erase("binary") == 1);
  CHECK(other_copy.erase("binary") == 1);
  CHECK(tree != copy);
  CHECK(tree != other_copy);
  CHECK(copy == other_copy);
  MESSAGE("prefix matching");
  auto matches = tree.prefixed_by("nothing");
  CHECK(matches.empty());
  matches = tree.prefixed_by("aff");
  CHECK(check_match(matches, {make_pair("affair", 3), make_pair("afford", 1)}));
  matches = tree.prefixed_by("bi");
  CHECK(check_match(matches, {make_pair("binary", 5), make_pair("bind", 6)}));
  matches = tree.prefixed_by("a");
  CHECK(check_match(matches,
                    {make_pair("apache", 0), make_pair("afford", 1),
                     make_pair("available", 2), make_pair("affair", 3),
                     make_pair("avenger", 4)}));
  matches = tree.prefixed_by("");
  CHECK(tree.size() == 10);
  CHECK(matches.size() == tree.size());
  for (const auto& m : matches) {
    auto it = tree.find(m->first);
    CHECK(it != tree.end());
    CHECK(it->first == m->first);
    CHECK(it->second == m->second);
  }
  for (const auto& p : tree)
    CHECK(find(matches, p));
  CHECK(tree.insert(make_pair("apache", -1)).second == false);
  CHECK(tree.size() == 10);
  CHECK(tree.find("apache")->second == 0);
  tree["apache"] = -1;
  CHECK(tree.find("apache")->second == -1);
  CHECK(tree.size() == 10);
  CHECK(tree.insert(make_pair("alien", 0)).second == true);
  CHECK(tree.size() == 11);
  CHECK(tree.find("alien")->second == 0);
  CHECK(tree.insert(make_pair("bro", 42)).second == true);
  CHECK(tree.size() == 12);
  matches = tree.prefixed_by("b");
  CHECK(check_match(matches,
                    {make_pair("bind", 6), make_pair("binary", 5),
                     make_pair("blind", 9), make_pair("brace", 8),
                     make_pair("bro", 42), make_pair("brother", 7)}));
  CHECK(tree.erase("nope") == 0);
  CHECK(tree.erase("a") == 0);
  CHECK(tree.size() == 12);
  CHECK(tree.erase("bro") == 1);
  CHECK(tree.size() == 11);
  matches = tree.prefixed_by("b");
  CHECK(check_match(matches,
                    {make_pair("bind", 6), make_pair("binary", 5),
                     make_pair("blind", 9), make_pair("brace", 8),
                     make_pair("brother", 7)}));
  CHECK(tree.insert(make_pair("bro", 42)).second == true);
  CHECK(tree.size() == 12);
  CHECK(tree.erase("brother") == 1);
  matches = tree.prefixed_by("b");
  CHECK(check_match(matches,
                    {make_pair("bind", 6), make_pair("binary", 5),
                     make_pair("blind", 9), make_pair("brace", 8),
                     make_pair("bro", 42)}));
  CHECK(tree.erase("brace") == 1);
  CHECK(tree.erase("bind") == 1);
  CHECK(tree.erase("blind") == 1);
  CHECK(tree.erase("binary") == 1);
  tree.clear();
  CHECK(tree.size() == 0);
  CHECK(tree.insert(make_pair("bro", 42)).second == true);
  CHECK(tree.insert(make_pair("bros", 1)).second == true);
  CHECK(tree.insert(make_pair("brother", 2)).second == true);
  CHECK(tree.size() == 3);
  matches = tree.prefixed_by("bro");
  CHECK(check_match(matches,
                    {make_pair("bro", 42), make_pair("bros", 1),
                     make_pair("brother", 2)}));
  matches = tree.prefix_of("bros");
  CHECK(check_match(matches,
                    {make_pair("bro", 42), make_pair("bros", 1)}));
  matches = tree.prefix_of("brothers");
  CHECK(check_match(matches,
                    {make_pair("bro", 42), make_pair("brother", 2)}));
  CHECK(tree.erase("brother") == 1);
  CHECK(tree.erase("bros") == 1);
  CHECK(tree.size() == 1);
  CHECK(tree.find("bro") != tree.end());
  CHECK(tree.find("bro")->first == "bro");
  CHECK(tree.find("bro")->second == 42);
  matches = tree.prefixed_by("bro");
  CHECK(check_match(matches, {make_pair("bro", 42)}));
  CHECK(tree.erase("bro") == 1);
  matches = tree.prefixed_by("");
  CHECK(matches.empty());
}
