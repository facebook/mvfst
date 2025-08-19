/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>
#include <string>

namespace quic {

/**
 * Convert the crypto error code to a string representation.
 * This function provides TLS-specific error descriptions for crypto errors.
 */
std::string cryptoErrorToString(TransportErrorCode code);

} // namespace quic
