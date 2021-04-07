load("@parsers_deps//:requirements.bzl", "requirement")

py_library(
    name = "output_parser",
    srcs = ["output_parser.py"],
)


py_binary(
    name = "example",
    srcs = ["example.py"],
    python_version = "PY3",
    deps = [
        requirement("glog"),
        ":output_parser"
    ],
)

py_binary(
    name = "jupyter",
    srcs = ["jupyter.py"],
    python_version = "PY3",
    deps = [
        requirement("notebook"),
        requirement("glog"),
        requirement("pandas"),
        requirement("matplotlib"),
        ":output_parser"
    ],
)
