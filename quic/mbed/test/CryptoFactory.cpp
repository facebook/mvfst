/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <fizz/crypto/aead/test/TestUtil.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/mbed/MbedCryptoFactory.h>

using namespace quic;

// TODO(damlaj): this isn't necessarily testing that the output is right, but
// rather than the output is equivalent to that of fizz (could be better, but
// at least this provides better than no value)
TEST(MakeInitialSecret, FizzMbedInitialSecretEquivalency) {
  FizzCryptoFactory fizz;
  MbedCryptoFactory mbed;

  for (int idx = 0; idx < 50; idx++) {
    // generate random conn id of max length
    auto randConnId = ConnectionId::createRandom(kMaxConnectionIdSize);

    // generate fizz & mbed client initial secret
    auto fizzClientSecret =
        fizz.makeClientInitialTrafficSecret(randConnId, QuicVersion::MVFST);
    auto mbedClientSecret =
        mbed.makeClientInitialTrafficSecret(randConnId, QuicVersion::MVFST);

    // test for equivalency
    EXPECT_TRUE(folly::IOBufEqualTo()(fizzClientSecret, mbedClientSecret));
  }
}

// sample taken from rfc9001 in appendix A
TEST(MakeClientInitialSecret, RFC9001SamplePacketProtection) {
  // These packets use an 8-byte client-chosen Destination Connection ID of
  // 0x8394c8f03e515708
  ConnectionId dstConnId({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});

  MbedCryptoFactory mbed;
  /**
   * The secrets for protecting client packets are:
   *
   * client_initial_secret
   * = HKDF-Expand-Label(initial_secret, "client in", "", 32)
   * = c00cf151ca5be075ed0ebfb5c80323c4 2d6b7db67881289af4008f1f6c357aea
   *
   * key = HKDF-Expand-Label(client_initial_secret, "quic key", "", 16) =
   * 1f369613dd76d5467730efcbe3b1a22d
   *
   * iv  = HKDF-Expand-Label(client_initial_secret, "quic iv", "", 12) =
   * fa044b2f42a3fd3b46fb255c
   *
   * hp  = HKDF-Expand-Label(client_initial_secret, "quic hp", "", 16) =
   * 9f50449e04a0e810283a1e9933adedd2
   */

  // construct client initial secret and compare w/ expected values
  auto clientInitialSecret =
      mbed.makeClientInitialTrafficSecret(dstConnId, QuicVersion::QUIC_V1);
  auto expectedClientInitialSecret = folly::IOBuf::copyBuffer(folly::unhexlify(
      "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"));
  EXPECT_TRUE(
      folly::IOBufEqualTo()(clientInitialSecret, expectedClientInitialSecret));

  // construct client initial aead and compare w/ expected key & iv values
  auto clientAead =
      mbed.getClientInitialCipher(dstConnId, QuicVersion::QUIC_V1);
  auto clientKey = clientAead->getKey();
  CHECK(clientKey.has_value());

  auto expectedClientInitialKey = folly::IOBuf::copyBuffer(
      folly::unhexlify("1f369613dd76d5467730efcbe3b1a22d"));
  auto expectedClientInitialIv =
      folly::IOBuf::copyBuffer(folly::unhexlify("fa044b2f42a3fd3b46fb255c"));
  EXPECT_TRUE(folly::IOBufEqualTo()(clientKey->key, expectedClientInitialKey));
  EXPECT_TRUE(folly::IOBufEqualTo()(clientKey->iv, expectedClientInitialIv));

  // construct client hp and compare w/ expected key
  auto clientHp =
      mbed.makeClientInitialHeaderCipher(dstConnId, QuicVersion::QUIC_V1);
  auto expectedClientHpKey = folly::IOBuf::copyBuffer(
      folly::unhexlify("9f50449e04a0e810283a1e9933adedd2"));
  EXPECT_TRUE(folly::IOBufEqualTo()(clientHp->getKey(), expectedClientHpKey));
}

// sample taken from rfc9001 in appendix A
TEST(MakeServerInitialSecret, RFC9001SamplePacketProtection) {
  // These packets use an 8-byte client-chosen Destination Connection ID of
  // 0x8394c8f03e515708
  ConnectionId dstConnId({0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08});

  MbedCryptoFactory mbed;
  /**
   * The secrets for protecting server packets are:
   *
   * server_initial_secret
   * = HKDF-Expand-Label(initial_secret, "server in", "", 32)
   * = 3c199828fd139efd216c155ad844cc81 fb82fa8d7446fa7d78be803acdda951b
   *
   * key = HKDF-Expand-Label(server_initial_secret, "quic key", "", 16)
   *     = cf3a5331653c364c88f0f379b6067e37
   *
   * iv  = HKDF-Expand-Label(server_initial_secret, "quic iv", "", 12)
   *     = 0ac1493ca1905853b0bba03e
   *
   * hp  = HKDF-Expand-Label(server_initial_secret, "quic hp", "", 16)
   *     = c206b8d9b9f0f37644430b490eeaa314
   */

  // construct server initial secret and compare w/ expected values
  auto serverInitialSecret =
      mbed.makeServerInitialTrafficSecret(dstConnId, QuicVersion::QUIC_V1);
  auto expectedServerInitialSecret = folly::IOBuf::copyBuffer(folly::unhexlify(
      "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b"));
  EXPECT_TRUE(
      folly::IOBufEqualTo()(serverInitialSecret, expectedServerInitialSecret));

  // construct server initial aead and compare w/ expected key & iv values
  auto serverAead =
      mbed.getServerInitialCipher(dstConnId, QuicVersion::QUIC_V1);
  auto serverKey = serverAead->getKey();
  CHECK(serverKey.has_value());

  auto expectedServerInitialKey = folly::IOBuf::copyBuffer(
      folly::unhexlify("cf3a5331653c364c88f0f379b6067e37"));
  auto expectedServerInitialIv =
      folly::IOBuf::copyBuffer(folly::unhexlify("0ac1493ca1905853b0bba03e"));
  EXPECT_TRUE(folly::IOBufEqualTo()(serverKey->key, expectedServerInitialKey));
  EXPECT_TRUE(folly::IOBufEqualTo()(serverKey->iv, expectedServerInitialIv));

  // construct server hp and compare w/ expected key
  auto serverHp =
      mbed.makeServerInitialHeaderCipher(dstConnId, QuicVersion::QUIC_V1);
  auto expectedServerHpKey = folly::IOBuf::copyBuffer(
      folly::unhexlify("c206b8d9b9f0f37644430b490eeaa314"));
  EXPECT_TRUE(folly::IOBufEqualTo()(serverHp->getKey(), expectedServerHpKey));
}
