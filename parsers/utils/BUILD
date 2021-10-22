cc_library(
    name = "utils",
    srcs = ["utils.cc"],
    hdrs= ["utils.h"],
    deps = [
        "@boost//:filesystem",
        "//external:glog",
        "//flashroute:address",
    ],
)

cc_binary(
    name = "unique_interface_counter",
    srcs = ["unique_interface_counter.cc"],
    deps = [
        "//external:glog",
        "//external:gflags",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse", 
        "//flashroute:dump_result",
        "//flashroute:address",
        "@boost//:filesystem",
        ":utils",
    ],
)

cc_binary(
    name = "dataset_comparison",
    srcs = ["dataset_comparison.cc"],
    deps = [
        "//external:glog",
        "//external:gflags",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse", 
        "//flashroute:dump_result",
        "//flashroute:address",
        "@boost//:filesystem",
        ":utils",
    ],
)

cc_binary(
    name = "frequency_analysis",
    srcs = ["frequency_analysis.cc"],
    deps = [
        "//external:glog",
        "//external:gflags",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse", 
        "//flashroute:dump_result",
        "//flashroute:address",
        "@boost//:filesystem",
        ":utils",
    ],
)

cc_binary(
    name = "route_similarity",
    srcs = ["route_similarity_analysis.cc"],
    deps = [
        "//external:glog",
        "//external:gflags",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse", 
        "//flashroute:dump_result",
        "//flashroute:address",
        "@boost//:filesystem",
        ":utils",
        "//flashroute:utils",
    ],
)


cc_binary(
    name = "route_generator",
    srcs = ["route_generator.cc"],
    deps = [
        "//external:glog",
        "//external:gflags",
        "@com_google_absl//absl/flags:flag",
        "@com_google_absl//absl/flags:parse", 
        "//flashroute:dump_result",
        "//flashroute:address",
        "@boost//:filesystem",
        ":utils",
        "//flashroute:utils",
    ],
)