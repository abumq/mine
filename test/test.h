#ifndef TEST_HELPERS_H_
#define TEST_HELPERS_H_

#include <vector>
#include <tuple>

#include <easylogging++.h>
#include <gtest/gtest.h>

template <typename... T>
using TestData = const std::vector<std::tuple<T...>>;

template <typename... T>
std::tuple<T...> TestCase(T... f) {
    return std::make_tuple(f...);
}

#define PARAM(v) std::get<v>(item)

#endif
