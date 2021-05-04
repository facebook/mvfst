/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
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

  MOCK_METHOD1(setKey, void(folly::ByteRange key));
  MOCK_CONST_METHOD1(mask, HeaderProtectionMask(folly::ByteRange));
  MOCK_CONST_METHOD0(keyLength, size_t());
  MOCK_CONST_METHOD0(getKey, const Buf&());

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
  MOCK_CONST_METHOD0(getCipherOverhead, size_t());

  MOCK_CONST_METHOD0(getKey, folly::Optional<TrafficKey>());
  MOCK_CONST_METHOD3(
      _inplaceEncrypt,
      std::unique_ptr<folly::IOBuf>(
          std::unique_ptr<folly::IOBuf>& plaintext,
          const folly::IOBuf* associatedData,
          uint64_t seqNum));
  std::unique_ptr<folly::IOBuf> inplaceEncrypt(
      std::unique_ptr<folly::IOBuf>&& plaintext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return _inplaceEncrypt(plaintext, associatedData, seqNum);
  }

  MOCK_CONST_METHOD3(
      _decrypt,
      std::unique_ptr<folly::IOBuf>(
          std::unique_ptr<folly::IOBuf>& ciphertext,
          const folly::IOBuf* associatedData,
          uint64_t seqNum));
  std::unique_ptr<folly::IOBuf> decrypt(
      std::unique_ptr<folly::IOBuf>&& ciphertext,
      const folly::IOBuf* associatedData,
      uint64_t seqNum) const override {
    return _decrypt(ciphertext, associatedData, seqNum);
  }

  MOCK_CONST_METHOD3(
      _tryDecrypt,
      folly::Optional<std::unique_ptr<folly::IOBuf>>(
          std::unique_ptr<folly::IOBuf>& ciphertext,
          const folly::IOBuf* associatedData,
          uint64_t seqNum));
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
