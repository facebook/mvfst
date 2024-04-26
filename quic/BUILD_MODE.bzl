# Copyright 2017 Facebook

""" build mode definitions for quic """

load("@fbcode//:BUILD_MODE.bzl", get_parent_modes = "get_empty_modes")
load("@fbcode_macros//build_defs:create_build_mode.bzl", "extend_build_modes")

_extra_cflags = [
]

_common_flags = [
    "-Wextra-semi",
    "-Wformat",
    "-Wformat-security",
    "-Wunused-function",
    "-Wunused-parameter",
    "-Wunused-variable",
    "-Wsign-compare",
    "-Wtype-limits",
    "-Wunused-value",
    # TODO this seems to break trunk (https://fb.workplace.com/groups/askbuck/permalink/4366767820038466/)
    # Re-enable after investigating the issue
    # "-Wno-module-import-in-extern-c",
]

_extra_clang_flags = _common_flags + [
    "-Wconstant-conversion",
    # Default value for clang (3.4) is 256, change it to GCC's default value
    # (https://fburl.com/23278774).
    "-ftemplate-depth=900",
    "-Wmismatched-tags",
    # Only check shadowing with Clang: gcc complains about constructor
    # argument shadowing
    "-Wshadow",
    "-Wunused-exception-parameter",
    "-Wheader-hygiene",
    "-Wall",
    "-Wextra",
]

_extra_gcc_flags = _common_flags + [
    "-Wall",
]

_modes = extend_build_modes(
    get_parent_modes(),
    c_flags = _extra_cflags,
    clang_flags = _extra_clang_flags,
    gcc_flags = _extra_gcc_flags,
    cxx_modular_headers = True,
)

def get_modes():
    """ Return modes for this file """
    return _modes
