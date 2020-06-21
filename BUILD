platform(
    name = "linux_x86",
    constraint_values = [
        "@platforms//os:linux",
        "@platforms//cpu:x86_32",
        ":glibc_2_25",
    ],
)

constraint_setting(name = "glibc_version")

constraint_value(
    name = "glibc_2_25",
    constraint_setting = ":glibc_version",
)

constraint_value(
    name = "glibc_2_26",
    constraint_setting = ":glibc_version",
)