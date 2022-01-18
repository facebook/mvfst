/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/dsr/Types.h>
#include <quic/dsr/frontend/PacketBuilder.h>

namespace quic {
uint32_t writeDSRStreamFrame(
    DSRPacketBuilderBase& packetBuilder,
    SendInstruction::Builder& instructionBuilder,
    StreamId id,
    uint64_t offset,
    uint64_t writeBufferLen,
    uint64_t flowControlLen,
    bool fin,
    uint64_t bufMetaStartingOffset);

} // namespace quic
