# Copyright 2017 Facebook

""" build mode definitions for quic """

load("@fbcode_macros//build_defs:create_build_mode.bzl", "create_build_mode")

_extra_cflags = [
]

_common_flags = [
    "-Wformat",
    "-Wformat-security",
    "-Wunused-variable",
    "-Wsign-compare",
]

_extra_clang_flags = _common_flags + [
    # Default value for clang (3.4) is 256, change it to GCC's default value
    # (https://fburl.com/23278774).
    "-ftemplate-depth=900",
    "-Wmismatched-tags",
    # Only check shadowing with Clang: gcc complains about constructor
    # argument shadowing
    "-Wshadow",
]

_extra_gcc_flags = _common_flags + [
    "-Wall",
]

_mode = create_build_mode(
    c_flags = _extra_cflags,
    clang_flags = _extra_clang_flags,
    gcc_flags = _extra_gcc_flags,
)

_modes = {
    "dbg": _mode,
    "dbgo": _mode,
    "dev": _mode,
    "opt": _mode,
}

def get_modes():
    """ Return modes for this file """
    return _modes
