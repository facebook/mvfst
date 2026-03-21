/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#ifdef MVFST_MBED
#include <quic/facebook/mbed/MbedPacketNumCipher.h> // @fb-only

namespace quic {

class Aes128PacketNumberCipher : public MbedPacketNumCipher {
 public:
  Aes128PacketNumberCipher() : MbedPacketNumCipher(CipherType::AESGCM128) {}
};

class Aes256PacketNumberCipher : public MbedPacketNumCipher {
 public:
  Aes256PacketNumberCipher() : MbedPacketNumCipher(CipherType::AESGCM256) {}
};

} // namespace quic

#else
#include <quic/fizz/handshake/FizzOpenSSLPacketNumberCipher.h>

namespace quic {
using Aes128PacketNumberCipher = FizzOpenSSLAes128PacketNumberCipher;
using Aes256PacketNumberCipher = FizzOpenSSLAes256PacketNumberCipher;
} // namespace quic

#endif
