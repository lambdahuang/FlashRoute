load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository", "new_git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "io_bazel_rules_go",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.22.2/rules_go-v0.22.2.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.22.2/rules_go-v0.22.2.tar.gz",
    ],
    sha256 = "142dd33e38b563605f0d20e89d9ef9eda0fc3cb539a14be1bdb1350de2eda659",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_register_toolchains()

http_archive(
    name = "bazel_gazelle",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/bazel-gazelle/releases/download/v0.20.0/bazel-gazelle-v0.20.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.20.0/bazel-gazelle-v0.20.0.tar.gz",
    ],
    sha256 = "d8c45ee70ec39a57e7a05e5027c32b1576cc7f16d9dd37135b0eddde45cf1b10",
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies", "go_repository")

gazelle_dependencies()

go_repository(
    name = "com_github_golang_glog",
    importpath = "github.com/golang/glog",
    commit = "23def4e6c14b4da8ac2ed8007337bc5eb5007998",
)

git_repository(
    name = "com_github_nelhage_rules_boost",
    commit = "fb9f3c9a6011f966200027843d894923ebc9cd0b",
    remote = "https://github.com/nelhage/rules_boost",
    shallow_since = "1626494016 -0700",
)

load("@com_github_nelhage_rules_boost//:boost/boost.bzl", "boost_deps")
boost_deps()

git_repository(
    name = "com_google_absl",
    commit = "278e0a071885a22dcd2fd1b5576cc44757299343",
    remote = "https://github.com/abseil/abseil-cpp.git",
    shallow_since = "1622559169 -0400",
)

new_git_repository(
    name = "glog_repo",
    remote = "https://github.com/google/glog.git",
    commit = "b6a5e0524c28178985f0d228e9eaa43808dbec3c",
    build_file = "glog.BUILD",
    shallow_since = "1476946406 +0900",
)

bind(
    name = "glog",
    actual = "@glog_repo//:glog"
)

git_repository(
    name   = "com_github_gflags",
    remote = "https://github.com/gflags/gflags.git",
    commit = "addd749114fab4f24b7ea1e0f2f837584389e52c",
    shallow_since = "1584534678 +0000",
)

bind(
    name = "gflags",
    actual = "@com_github_gflags//:gflags",
)

# Python Components Configuration
http_archive(
    name = "rules_python",
    url = "https://github.com/bazelbuild/rules_python/releases/download/0.1.0/rules_python-0.1.0.tar.gz",
    sha256 = "b6d46438523a3ec0f3cead544190ee13223a52f6a6765a29eae7b7cc24cc83a0",
)

# Only needed for PIP support:
load("@rules_python//python:pip.bzl", "pip_install")

pip_install(
    name = "parsers_deps",
    requirements = "//parsers:requirements.txt",
    python_interpreter = "python3"
)

new_git_repository(
    name = "googletest",
    build_file = "gmock.BUILD",
    remote = "https://github.com/google/googletest",
    tag = "release-1.10.0",
)
