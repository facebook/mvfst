/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/portability/GMock.h>
#include <quic/codec/PacketNumberCipher.h>
#include <quic/fizz/handshake/FizzCryptoFactory.h>
#include <quic/handshake/Aead.h>
#include <quic/handshake/HandshakeLayer.h>

namespace quic {
namespace test {

// Forward declaration
std::array<uint8_t, kStatelessResetTokenSecretLength> getRandSecret();
std::unique_ptr<folly::IOBuf> getProtectionKey();

class MockPacketNumberCipher : public PacketNumberCipher {
 public:
  virtual ~MockPacketNumberCipher() = default;

  MOCK_METHOD(void, setKey, (folly::ByteRange key));
  MOCK_METHOD(HeaderProtectionMask, mask, (folly::ByteRange), (const));
  MOCK_METHOD(size_t, keyLength, (), (const));
  MOCK_METHOD(const Buf&, getKey, (), (const));

  void setDefaultKey() {
    packetProtectionKey_ = getProtectionKey();
    ON_CALL(*this, getKey())
        .WillByDefault(testing::ReturnRef(packetProtectionKey_));
  }

 private:
  Buf packetProtectionKey_;
};

class MockAead : public Aead {
 public:
  MOCK_METHOD(size_t, getCipherOverhead, (), (const));

  MOCK_METHOD(folly::Optional<TrafficKey>, getKey, (), (const));
  MOCK_METHOD(
      std::unique_ptr<folly::IOBuf>,
      _inplaceEncrypt,
      (std::unique_ptr<folly::IOBuf> & plaintext,
       const folly::IOBuf* associatedData,
       uint64_t seqNum),
      (const));
  std::unique_ptr<folly::IOBuf> inplaceEncrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return _inplaceEncrypt(plaintext, associatedData, seqNum);
  }

  MOCK_METHOD(
      std::unique_ptr<folly::IOBuf>,
      _decrypt,
      (std::unique_ptr<folly::IOBuf> & ciphertext,
       const folly::IOBuf* associatedData,
       uint64_t seqNum),
      (const));
  std::unique_ptr<folly::IOBuf> decrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return _decrypt(ciphertext, associatedData, seqNum);
  }

  MOCK_METHOD(
      folly::Optional<std::unique_ptr<folly::IOBuf>>,
      _tryDecrypt,
      (std::unique_ptr<folly::IOBuf> & ciphertext,
       const folly::IOBuf* associatedData,
       uint64_t seqNum),
      (const));
  folly::Optional<std::unique_ptr<folly::IOBuf>> tryDecrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return _tryDecrypt(ciphertext, associatedData, seqNum);
  }

  void setDefaults() {
    using namespace testing;
    ON_CALL(*this, _inplaceEncrypt(_, _, _))
        .WillByDefault(InvokeWithoutArgs(
            []() { return folly::IOBuf::copyBuffer("ciphertext"); }));
    ON_CALL(*this, _decrypt(_, _, _)).WillByDefault(InvokeWithoutArgs([]() {
      return folly::IOBuf::copyBuffer("plaintext");
    }));
    ON_CALL(*this, _tryDecrypt(_, _, _)).WillByDefault(InvokeWithoutArgs([]() {
      return folly::IOBuf::copyBuffer("plaintext");
    }));
  }
};

} // namespace test
} // namespace quic
