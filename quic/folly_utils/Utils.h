/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/io/Cursor.h>
#include <quic/common/Optional.h>

namespace quic::follyutils {

/**
 * Reads an integer out of the cursor and returns a pair with the integer and
 * the numbers of bytes read, or std::nullopt if there are not enough bytes to
 * read the int. It only advances the cursor in case of success.
 */
Optional<std::pair<uint64_t, size_t>> decodeQuicInteger(
    folly::io::Cursor& cursor,
    uint64_t atMost = sizeof(uint64_t));

} // namespace quic::follyutils
