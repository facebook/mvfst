/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

// Server version: QUIC_ENUM expands to BETTER_ENUM with reflection support.
// On mobile, this header is aliased to QuicEnumMobile.h which uses plain
// enum class to reduce binary size (~6KB per enum).

#include <folly/lang/Assume.h>
#include <quic/common/third-party/enum.h>

#define QUIC_ENUM(Name, Type, ...) BETTER_ENUM(Name, Type, __VA_ARGS__)

// Helper macro to construct an enum from an integral value.
// On server (BETTER_ENUM), uses _from_integral_unchecked().
// On mobile (plain enum class), uses static_cast.
#define QUIC_ENUM_FROM_INTEGRAL_UNCHECKED(EnumType, value) \
  EnumType::_from_integral_unchecked(value)
