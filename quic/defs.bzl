"""
[mvfst]
    use_libev = {False|[True]}
"""

load("@fbcode_macros//build_defs:autodeps_rule.bzl", "autodeps_rule")
load("@fbcode_macros//build_defs:cpp_library.bzl", "cpp_library")
load("@fbsource//tools/build_defs:buckconfig.bzl", "read_bool")
load(
    "@fbsource//tools/build_defs:default_platform_defs.bzl",
    "ANDROID",
    "APPLE",
    "CXX",
    "FBCODE",
    "IOS",
    "MACOSX",
    "WATCHOS",
    "WINDOWS",
)
load("@fbsource//tools/build_defs:fb_xplat_cxx_binary.bzl", "fb_xplat_cxx_binary")
load("@fbsource//tools/build_defs:fb_xplat_cxx_library.bzl", "fb_xplat_cxx_library")
load("@fbsource//tools/build_defs:fb_xplat_cxx_test.bzl", "fb_xplat_cxx_test")
load("@fbsource//tools/build_defs:fbsource_utils.bzl", "is_arvr_mode")
load("@fbsource//xplat/pfh/Infra_Networking_Core:DEFS.bzl", "Infra_Networking_Core")

CXXFLAGS = [
    "-frtti",
    "-fexceptions",
    "-Wno-nullability-completeness",
    "-Wno-implicit-fallthrough",
]

FBANDROID_CXXFLAGS = [
    "-ffunction-sections",
    "-Wno-nullability-completeness",
    "-fstack-protector-strong",
]

FBOBJC_CXXFLAGS = [
    "-Wno-global-constructors",
    "-fstack-protector-strong",
]

WINDOWS_MSVC_CXXFLAGS = [
    "/EHs",
    "/D_ENABLE_EXTENDED_ALIGNED_STORAGE",
]

WINDOWS_CLANG_CXX_FLAGS = [
    "-Wno-deprecated-declarations",
    "-Wno-microsoft-cast",
    "-Wno-missing-braces",
    "-Wno-unused-function",
    "-Wno-undef",
    "-DBOOST_HAS_THREADS",
    "-D_ENABLE_EXTENDED_ALIGNED_STORAGE",
]

DEFAULT_APPLE_SDKS = (IOS, MACOSX, WATCHOS)
DEFAULT_PLATFORMS = (CXX, ANDROID, APPLE, FBCODE, WINDOWS)

def _compute_include_directories():
    base_path = native.package_name()
    if base_path == "xplat/quic":
        return [".."]
    quic_path = base_path[6:]
    return ["/".join(len(quic_path.split("/")) * [".."])]

def use_libev():
    return read_bool("mvfst", "use_libev", False)

def mvfst_cpp_library(name, autodeps_skip = False, **kwargs):
    preprocessor_flags = kwargs.pop("preprocessor_flags", [])
    exported_deps = kwargs.pop("exported_deps", [])
    mvfst_mobile_exported_deps = kwargs.pop("mvfst_mobile_exported_deps", [])
    mvfst_non_mobile_exported_deps = kwargs.pop("mvfst_non_mobile_exported_deps", [])
    exported_external_deps = kwargs.pop("exported_external_deps", [])
    if use_libev():
        preprocessor_flags += ["-DMVFST_USE_LIBEV"]
        exported_external_deps += mvfst_mobile_exported_deps
    else:
        exported_deps += mvfst_non_mobile_exported_deps

    kwargs["preprocessor_flags"] = preprocessor_flags
    kwargs["exported_deps"] = exported_deps
    kwargs["exported_external_deps"] = exported_external_deps
    cpp_library(name = name, autodeps_skip = True, **kwargs)

    if not autodeps_skip:
        autodeps_rule(
            name = name,
            type = "mvfst_cpp_library",
            attrs = kwargs,
        )

def mvfst_cxx_library(
        name,
        srcs = (),
        headers = (),
        exported_headers = (),
        raw_headers = (),
        deps = (),
        exported_deps = (),
        force_static = False,
        apple_sdks = None,
        platforms = None,
        enable_static_variant = True,
        labels = (),
        fbandroid_labels = (),
        fbobjc_labels = (),
        header_namespace = "",
        **kwargs):
    """Translate a simpler declartion into the more complete library target"""

    # Set default platform settings. `()` means empty, whereas None
    # means default
    if apple_sdks == None:
        apple_sdks = DEFAULT_APPLE_SDKS
    if platforms == None:
        platforms = DEFAULT_PLATFORMS

    # We use gflags on fbcode platforms, which don't mix well when mixing static
    # and dynamic linking.
    if not is_arvr_mode():
        force_static = select({
            "DEFAULT": force_static,
            "ovr_config//runtime:fbcode": False,
        })

    exported_preprocessor_flags = kwargs.pop("exported_preprocessor_flags", [])
    mvfst_mobile_exported_deps = kwargs.pop("mvfst_mobile_exported_deps", [])
    mvfst_non_mobile_exported_deps = kwargs.pop("mvfst_non_mobile_exported_deps", [])
    if use_libev():
        exported_preprocessor_flags += ["-DMVFST_USE_LIBEV"]
        exported_deps = list(exported_deps) + mvfst_mobile_exported_deps
    else:
        exported_deps = list(exported_deps) + mvfst_non_mobile_exported_deps

    fb_xplat_cxx_library(
        name = name,
        srcs = srcs,
        header_namespace = header_namespace,
        headers = headers,
        exported_headers = exported_headers,
        raw_headers = raw_headers,
        public_include_directories = _compute_include_directories(),
        deps = deps,
        exported_deps = exported_deps,
        force_static = force_static,
        apple_sdks = apple_sdks,
        platforms = platforms,
        enable_static_variant = enable_static_variant,
        labels = list(labels),
        fbandroid_labels = list(fbandroid_labels),
        fbobjc_labels = list(fbobjc_labels),
        compiler_flags = kwargs.pop("compiler_flags", []) + CXXFLAGS,
        exported_preprocessor_flags = exported_preprocessor_flags,
        windows_compiler_flags = kwargs.pop("windows_compiler_flags", []) + CXXFLAGS + WINDOWS_CLANG_CXX_FLAGS,
        fbobjc_compiler_flags = kwargs.pop("fbobjc_compiler_flags", []) +
                                FBOBJC_CXXFLAGS,
        fbcode_compiler_flags_override = kwargs.pop("fbcode_compiler_flags", []),
        fbandroid_compiler_flags = kwargs.pop("fbandroid_compiler_flags", []) +
                                   FBANDROID_CXXFLAGS,
        windows_msvc_compiler_flags_override = kwargs.pop("windows_msvc_compiler_flags_override", WINDOWS_MSVC_CXXFLAGS),
        windows_preferred_linkage = "static",
        visibility = kwargs.pop("visibility", ["PUBLIC"]),
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        feature = Infra_Networking_Core,
        **kwargs
    )

def mvfst_cxx_test(
        name,
        srcs,
        raw_headers = [],
        deps = []):
    fb_xplat_cxx_test(
        name = name,
        srcs = srcs,
        raw_headers = raw_headers,
        include_directories = [
            "..",
        ],
        deps = deps,
        platforms = (CXX,),
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
    )

def mvfst_cxx_binary(
        name,
        srcs,
        raw_headers = [],
        deps = [],
        **kwargs):
    fb_xplat_cxx_binary(
        name = name,
        srcs = srcs,
        raw_headers = raw_headers,
        compiler_flags = kwargs.pop("compiler_flags", []) + CXXFLAGS,
        include_directories = [
            "..",
        ],
        deps = deps,
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        platforms = (CXX,),
    )

def mu_cxx_library(
        name,
        srcs = (),
        headers = (),
        exported_headers = (),
        raw_headers = (),
        deps = (),
        exported_deps = (),
        force_static = False,
        apple_sdks = None,
        platforms = None,
        enable_static_variant = True,
        labels = (),
        fbandroid_labels = (),
        fbobjc_labels = (),
        header_namespace = "",
        **kwargs):
    """Translate a simpler declartion into the more complete library target"""

    # Set default platform settings. `()` means empty, whereas None
    # means default
    if apple_sdks == None:
        apple_sdks = DEFAULT_APPLE_SDKS
    if platforms == None:
        platforms = DEFAULT_PLATFORMS

    # We use gflags on fbcode platforms, which don't mix well when mixing static
    # and dynamic linking.
    if not is_arvr_mode():
        force_static = select({
            "DEFAULT": force_static,
            "ovr_config//runtime:fbcode": False,
        })

    fb_xplat_cxx_library(
        name = name,
        srcs = srcs,
        header_namespace = header_namespace,
        headers = headers,
        exported_headers = exported_headers,
        raw_headers = raw_headers,
        public_include_directories = _compute_include_directories(),
        deps = deps,
        exported_deps = exported_deps,
        force_static = force_static,
        apple_sdks = apple_sdks,
        platforms = platforms,
        enable_static_variant = enable_static_variant,
        labels = list(labels),
        fbandroid_labels = list(fbandroid_labels),
        fbobjc_labels = list(fbobjc_labels),
        compiler_flags = kwargs.pop("compiler_flags", []) + CXXFLAGS,
        windows_compiler_flags = kwargs.pop("windows_compiler_flags", []) + CXXFLAGS + WINDOWS_CLANG_CXX_FLAGS,
        fbobjc_compiler_flags = kwargs.pop("fbobjc_compiler_flags", []) +
                                FBOBJC_CXXFLAGS,
        fbcode_compiler_flags_override = kwargs.pop("fbcode_compiler_flags", []),
        fbandroid_compiler_flags = kwargs.pop("fbandroid_compiler_flags", []) +
                                   FBANDROID_CXXFLAGS,
        windows_msvc_compiler_flags_override = kwargs.pop("windows_msvc_compiler_flags_override", WINDOWS_MSVC_CXXFLAGS),
        windows_preferred_linkage = "static",
        visibility = kwargs.pop("visibility", ["PUBLIC"]),
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        feature = Infra_Networking_Core,
        **kwargs
    )

def mu_cxx_test(
        name,
        srcs,
        raw_headers = [],
        deps = []):
    fb_xplat_cxx_test(
        name = name,
        srcs = srcs,
        raw_headers = raw_headers,
        include_directories = [
            "..",
        ],
        deps = deps,
        platforms = (CXX,),
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
    )

def mu_cxx_binary(
        name,
        srcs,
        raw_headers = [],
        deps = [],
        **kwargs):
    fb_xplat_cxx_binary(
        name = name,
        srcs = srcs,
        raw_headers = raw_headers,
        compiler_flags = kwargs.pop("compiler_flags", []) + CXXFLAGS,
        include_directories = [
            "..",
        ],
        deps = deps,
        contacts = ["oncall+traffic_protocols@xmail.facebook.com"],
        platforms = (CXX,),
    )
