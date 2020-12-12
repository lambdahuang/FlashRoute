cc_library(
    name = "blacklist",
    srcs = ["blacklist.cc"],
    hdrs = ["blacklist.h"],
    copts = ["-std=c++14"],
    deps = [
        ":utils",
        ":traceroute",
        "@boost//:format",
        "@com_google_absl//absl/strings",
    ]
)

cc_test(
    name = "blacklist_test",
    srcs = ["blacklist_test.cc"],
    deps = [
        ":blacklist",
        ":traceroute",
        "@googletest//:gtest_main",
        "@googletest//:gtest",
    ],
)

cc_library(
    name = "network",
    hdrs = ["network.h"],
    srcs = ["network.cc"],
    copts = ["-std=c++14"],
    deps = [
        ":address",
        ":prober",
        ":bounded_buffer",
        ":utils",
        "@boost//:asio",
        "@boost//:circular_buffer",
        "//external:glog",
    ],
)

cc_library(
    name = "dcb_manager",
    hdrs = [
        "dcb_manager.h"
    ],
    srcs = [
        "dcb_manager.cc"
    ],
    copts = ["-std=c++14"],
    deps = [
        ":address",
        ":dcb",
        ":utils",
    ],
)

cc_library(
    name = "dcb",
    hdrs = [
        "dcb.h"
    ],
    srcs = [
        "dcb.cc"
    ],
    copts = ["-std=c++14"],
    deps = [
        ":address",
        ":utils",
    ],
)


cc_library(
    name = "traceroute",
    hdrs = [
        "traceroute.h",
    ],
    srcs = [
        "traceroute.cc",
    ],
    copts = ["-std=c++14"],
    deps = [
        ":address",
        ":dcb",
        ":dcb_manager",
        ":utils",
        ":network",
        ":prober",
        "dump_result",
        "@boost//:asio",
        "@boost//:format",
        "@com_google_absl//absl/strings",
        "//external:glog",
    ],
)

cc_library(
    name = "address",
    hdrs = [
        "address.h",
    ],
    srcs = [
        "address.cc",
    ],
    copts = ["-std=c++14"],
)

cc_library(
    name = "utils",
    hdrs = ["utils.h"],
    srcs = ["utils.cc"],
    copts = ["-std=c++14"],
    deps = [
        ":address",
        "@boost//:process",
        "@com_google_absl//absl/strings",
        "//external:glog",
    ],
)

cc_library(
    name = "bounded_buffer",
    hdrs = ["bounded_buffer.h"],
    srcs = ["bounded_buffer.cc"],
    copts = ["-std=c++14"],
    deps = [
        "@boost//:circular_buffer",
        "@boost//:bind",
        "@boost//:thread",
        "@boost//:timer",
    ],
)

cc_library(
    name = "hitlist",
    hdrs = ["hitlist.h"],
    srcs = ["hitlist.cc"],
    copts = ["-std=c++14"],
    deps = [
        "utils",
        ":traceroute",
        "@boost//:format",
        "@com_google_absl//absl/strings",
    ],
)

cc_library(
    name = "targets",
    hdrs = ["targets.h"],
    srcs = ["targets.cc"],
    copts = ["-std=c++14"],
    deps = [
        ":address",
        ":dcb_manager",
        ":utils",
        "//external:glog",
        "@boost//:format",
    ],
)
#include "absl/strings/str_cat.h"

cc_binary(
    name = "flashroute",
    srcs = ["main.cc"],
    copts = ["-std=c++14"],
    deps = [
        ":dcb_manager",
        ":prober",
        ":blacklist",
        "hitlist",
        ":targets",
        ":utils",
        "@boost//:asio",
        "@boost//:format",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse",
        "//external:gflags",
        "//external:glog",
    ],
)

cc_test(
    name = "utils_tests",
    srcs = ["utils_test.cc"],
    deps = [
        ":utils",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "prober",
    hdrs = [
        "prober.h",
        "udp_prober.h",
        "udp_idempotent_prober.h"],
    srcs = [
        "udp_prober.cc",
        "udp_idempotent_prober.cc"],
    copts = ["-std=c++14"],
    deps = [
        ":address",
        ":utils",
        "//external:glog",
    ],
)

cc_test(
    name = "prober_test",
    srcs = ["udp_prober_test.cc"],
    deps = [
        ":prober",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "dump_result",
    hdrs = ["dump_result.h"],
    srcs = ["dump_result.cc"],
    copts = ["-std=c++14"],
    deps = [
        ":utils",
        ":bounded_buffer",
        "//external:glog",
    ],
)