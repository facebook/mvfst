/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/fizz/handshake/QuicFizzFactory.h>

namespace {

class QuicPlaintextReadRecordLayer : public fizz::PlaintextReadRecordLayer {
 public:
  ~QuicPlaintextReadRecordLayer() override = default;

  ReadResult<fizz::TLSMessage> read(
      folly::IOBufQueue& buf,
      fizz::Aead::AeadOptions) override {
    if (buf.empty()) {
      return folly::none;
    }
    fizz::TLSMessage msg;
    msg.type = fizz::ContentType::handshake;
    msg.fragment = buf.move();
    return ReadResult<fizz::TLSMessage>::from(std::move(msg));
  }
};

class QuicEncryptedReadRecordLayer : public fizz::EncryptedReadRecordLayer {
 public:
  ~QuicEncryptedReadRecordLayer() override = default;

  explicit QuicEncryptedReadRecordLayer(fizz::EncryptionLevel encryptionLevel)
      : fizz::EncryptedReadRecordLayer(encryptionLevel) {}

  ReadResult<fizz::TLSMessage> read(
      folly::IOBufQueue& buf,
      fizz::Aead::AeadOptions) override {
    if (buf.empty()) {
      return folly::none;
    }
    fizz::TLSMessage msg;
    msg.type = fizz::ContentType::handshake;
    msg.fragment = buf.move();
    return ReadResult<fizz::TLSMessage>::from(std::move(msg));
  }
};

class QuicPlaintextWriteRecordLayer : public fizz::PlaintextWriteRecordLayer {
 public:
  ~QuicPlaintextWriteRecordLayer() override = default;

  fizz::TLSContent write(
      fizz::TLSMessage&& msg,
      fizz::Aead::AeadOptions /*options*/) const override {
    fizz::TLSContent content;
    content.data = std::move(msg.fragment);
    content.contentType = msg.type;
    content.encryptionLevel = getEncryptionLevel();
    return content;
  }

  fizz::TLSContent writeInitialClientHello(
      std::unique_ptr<folly::IOBuf> encodedClientHello) const override {
    return write(
        fizz::TLSMessage{
            fizz::ContentType::handshake, std::move(encodedClientHello)},
        fizz::Aead::AeadOptions());
  }
};

class QuicEncryptedWriteRecordLayer : public fizz::EncryptedWriteRecordLayer {
 public:
  ~QuicEncryptedWriteRecordLayer() override = default;

  explicit QuicEncryptedWriteRecordLayer(fizz::EncryptionLevel encryptionLevel)
      : EncryptedWriteRecordLayer(encryptionLevel) {}

  fizz::TLSContent write(
      fizz::TLSMessage&& msg,
      fizz::Aead::AeadOptions /*options*/) const override {
    fizz::TLSContent content;
    content.data = std::move(msg.fragment);
    content.contentType = msg.type;
    content.encryptionLevel = getEncryptionLevel();
    return content;
  }
};

} // namespace

namespace quic {

std::unique_ptr<fizz::PlaintextReadRecordLayer>
QuicFizzFactory::makePlaintextReadRecordLayer() const {
  return std::make_unique<QuicPlaintextReadRecordLayer>();
}

std::unique_ptr<fizz::PlaintextWriteRecordLayer>
QuicFizzFactory::makePlaintextWriteRecordLayer() const {
  return std::make_unique<QuicPlaintextWriteRecordLayer>();
}

std::unique_ptr<fizz::EncryptedReadRecordLayer>
QuicFizzFactory::makeEncryptedReadRecordLayer(
    fizz::EncryptionLevel encryptionLevel) const {
  return std::make_unique<QuicEncryptedReadRecordLayer>(encryptionLevel);
}

std::unique_ptr<fizz::EncryptedWriteRecordLayer>
QuicFizzFactory::makeEncryptedWriteRecordLayer(
    fizz::EncryptionLevel encryptionLevel) const {
  return std::make_unique<QuicEncryptedWriteRecordLayer>(encryptionLevel);
}

} // namespace quic
