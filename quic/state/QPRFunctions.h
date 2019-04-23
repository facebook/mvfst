/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

// Copyright 2004-present Facebook. All Rights Reserved.

#pragma once

#include <quic/codec/Types.h>
#include <quic/state/StateData.h>

namespace quic {

/**
 * advance the currentReceiveOffset for a stream
 */
folly::Optional<uint64_t> advanceCurrentReceiveOffset(
    QuicStreamState* stream,
    uint64_t offset);

/**
 * processing upon receipt of MinStreamDataFrame
 */
void onRecvMinStreamDataFrame(
    QuicStreamState* stream,
    const MinStreamDataFrame& frame,
    PacketNum packetNum);

/**
 * advance the minimum retransmittable offset for a stream
 */
folly::Optional<uint64_t> advanceMinimumRetransmittableOffset(
    QuicStreamState* stream,
    uint64_t minimumRetransmittableOffset);

/**
 * processing upon receipt of ExpiredStreamDataFrame
 */
void onRecvExpiredStreamDataFrame(
    QuicStreamState* stream,
    const ExpiredStreamDataFrame& frame);
} // namespace quic
