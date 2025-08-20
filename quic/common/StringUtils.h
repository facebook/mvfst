/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <string>

#include <quic/QuicException.h>
#include <quic/common/Expected.h>

namespace quic {

/**
 * Convert input to hexadecimal representation.
 */
std::string hexlify(const std::string& input);

/**
 * Get binary data from hexadecimal representation.
 */
quic::Expected<std::string, QuicError> unhexlify(const std::string& input);

} // namespace quic
