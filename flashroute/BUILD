cc_library(
    name = "blacklist",
    srcs = ["blacklist.cc"],
    hdrs = ["blacklist.h"],
    copts = ["-std=c++14"],
    deps = [
        ":address",
        ":utils",
        ":traceroute",
        "@boost//:format",
        "@com_google_absl//absl/strings",
    ]
)

# cc_test(
#     name = "blacklist_test",
#     srcs = ["blacklist_test.cc"],
#     deps = [
#         ":blacklist",
#         ":traceroute",
#         "@googletest//:gtest_main",
#         "@googletest//:gtest",
#     ],
# )

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
        ":dump_result",
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
    deps = [
        "@com_google_absl//absl/random",
    ],
    visibility = ["//visibility:public"],
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
        ":blacklist",
        ":bogon_filter",
        ":dcb_manager",
        ":utils",
        "//external:glog",
        "@boost//:format",
    ],
)

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
        ":single_host",
        ":output_parser",
        ":bogon_filter",
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
        ":address",
        "@googletest//:gtest_main",
    ],
)

cc_library(
    name = "prober",
    hdrs = [
        "prober.h",
        "udp_prober.h",
        "udp_prober_v6.h",
        "udp_idempotent_prober.h"],
    srcs = [
        "udp_prober.cc",
        "udp_prober_v6.cc",
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
    visibility = ["//visibility:public"],
    deps = [
        ":address",
        ":utils",
        ":bounded_buffer",
        "//external:glog",
    ],
)

cc_library(
    name = "single_host",
    hdrs = ["single_host.h"],
    srcs = ["single_host.cc"],
    copts = ["-std=c++14"],
    deps = [
        ":address",
        ":utils",
        ":network",
        ":prober",
        ":dcb_manager",
        "//external:glog",
        "@boost//:format",
    ],
)

cc_library(
    name = "output_parser",
    hdrs = ["output_parser.h"],
    srcs = ["output_parser.cc"],
    copts = ["-std=c++14"],
    deps = [
        ":utils",
        ":dcb_manager",
        "//external:glog",
    ],
)

cc_library(
    name = "trie",
    hdrs = ["trie.h"],
    srcs = ["trie.cc"],
    copts = ["-std=c++14"],
    deps = [
        ":utils",
        ":address",
        "//external:glog",
    ],
)

cc_library(
    name = "bogon_filter",
    hdrs = ["bogon_filter.h"],
    srcs = ["bogon_filter.cc"],
    copts = ["-std=c++14"],
    deps = [
        ":utils",
        ":trie",
        "//external:glog",
        "@com_google_absl//absl/strings",
    ],
)

cc_test(
    name = "trie_test",
    srcs = ["trie_test.cc"],
    deps = [
        ":utils",
        ":trie",
        "@googletest//:gtest_main",
    ],
)