/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/io/IOBuf.h>
#include <folly/portability/GTest.h>
#include <quic/codec/QuicInteger.h>
#include <quic/common/Optional.h>
#include <quic/common/StringUtils.h>

#include <quic/QuicException.h>
#include <quic/codec/QuicInteger.h>
#include <quic/folly_utils/Utils.h>

using namespace testing;
using namespace folly;

namespace quic::test {

struct IntegerParams {
  uint64_t decoded;
  std::string hexEncoded;
  bool error{false};
  uint8_t encodedLength{8};
};

class QuicIntegerDecodeTest : public TestWithParam<IntegerParams> {};

class QuicIntegerEncodeTest : public TestWithParam<IntegerParams> {};

TEST_P(QuicIntegerDecodeTest, DecodeTrim) {
  auto encodedBytesOpt = quic::unhexlify(GetParam().hexEncoded);
  CHECK(encodedBytesOpt.has_value())
      << "Failed to unhexlify: " << GetParam().hexEncoded;
  std::string encodedBytes = encodedBytesOpt.value();

  for (int atMost = 0; atMost <= GetParam().encodedLength; atMost++) {
    auto wrappedEncoded = IOBuf::copyBuffer(encodedBytes);
    wrappedEncoded->trimEnd(std::min(
        (unsigned long)(wrappedEncoded->computeChainDataLength()),
        (unsigned long)(GetParam().encodedLength - atMost)));
    Cursor cursor(wrappedEncoded.get());
    auto originalLength = cursor.length();
    auto decodedValue = quic::decodeQuicInteger(cursor);
    if (GetParam().error || atMost != GetParam().encodedLength) {
      EXPECT_FALSE(decodedValue.has_value());
      EXPECT_EQ(cursor.length(), originalLength);
    } else {
      EXPECT_EQ(decodedValue->first, GetParam().decoded);
      EXPECT_EQ(decodedValue->second, GetParam().encodedLength);
      EXPECT_EQ(cursor.length(), originalLength - GetParam().encodedLength);
    }
  }
}

TEST_P(QuicIntegerDecodeTest, DecodeAtMost) {
  auto encodedBytesOpt = quic::unhexlify(GetParam().hexEncoded);
  CHECK(encodedBytesOpt.has_value())
      << "Failed to unhexlify: " << GetParam().hexEncoded;
  std::string encodedBytes = encodedBytesOpt.value();
  auto wrappedEncoded = IOBuf::copyBuffer(encodedBytes);

  for (int atMost = 0; atMost <= GetParam().encodedLength; atMost++) {
    Cursor cursor(wrappedEncoded.get());
    auto originalLength = cursor.length();
    auto decodedValue = quic::decodeQuicInteger(cursor, atMost);
    if (GetParam().error || atMost != GetParam().encodedLength) {
      EXPECT_FALSE(decodedValue.has_value());
      EXPECT_EQ(cursor.length(), originalLength);
    } else {
      EXPECT_EQ(decodedValue->first, GetParam().decoded);
      EXPECT_EQ(decodedValue->second, GetParam().encodedLength);
      EXPECT_EQ(cursor.length(), originalLength - GetParam().encodedLength);
    }
  }
}

TEST_P(QuicIntegerEncodeTest, Encode) {
  auto queue = folly::IOBuf::create(0);
  BufAppender appender(queue.get(), 10);
  auto appendOp = [&](auto val) { appender.writeBE(val); };
  if (GetParam().error) {
    auto size = encodeQuicInteger(GetParam().decoded, appendOp);
    EXPECT_TRUE(size.hasError());
    EXPECT_EQ(size.error(), TransportErrorCode::INTERNAL_ERROR);
    return;
  }
  auto written = encodeQuicInteger(GetParam().decoded, appendOp);
  auto encodedValue = quic::hexlify(queue->to<std::string>());
  LOG(INFO) << "encoded=" << encodedValue;
  LOG(INFO) << "expected=" << GetParam().hexEncoded;

  EXPECT_EQ(encodedValue, GetParam().hexEncoded);
  EXPECT_EQ(*written, encodedValue.size() / 2);
}

TEST_P(QuicIntegerEncodeTest, GetSize) {
  auto size = getQuicIntegerSize(GetParam().decoded);
  if (GetParam().error) {
    EXPECT_TRUE(size.hasError());
    ASSERT_NE(size.error().code.asTransportErrorCode(), nullptr);
    EXPECT_EQ(
        *size.error().code.asTransportErrorCode(),
        TransportErrorCode::INTERNAL_ERROR);
    return;
  }
  EXPECT_EQ(*size, GetParam().hexEncoded.size() / 2);
}

TEST_F(QuicIntegerEncodeTest, ForceFourBytes) {
  auto queue = folly::IOBuf::create(0);
  BufAppender appender(queue.get(), 10);
  auto appendOp = [&](auto val) { appender.writeBE(val); };
  EXPECT_EQ(4, *encodeQuicInteger(37, appendOp, 4));
  auto encodedValue = quic::hexlify(queue->to<std::string>());
  EXPECT_EQ("80000025", encodedValue);
}

TEST_F(QuicIntegerEncodeTest, ForceEightBytes) {
  auto queue = folly::IOBuf::create(0);
  BufAppender appender(queue.get(), 10);
  auto appendOp = [&](auto val) { appender.writeBE(val); };
  EXPECT_EQ(8, *encodeQuicInteger(37, appendOp, 8));
  auto encodedValue = quic::hexlify(queue->to<std::string>());
  EXPECT_EQ("c000000000000025", encodedValue);
}

TEST_F(QuicIntegerEncodeTest, ForceWrongBytes) {
  auto queue = folly::IOBuf::create(0);
  BufAppender appender(queue.get(), 10);
  auto appendOp = [&](auto val) { appender.writeBE(val); };
  EXPECT_DEATH((void)encodeQuicInteger(15293, appendOp, 1), "");
}

INSTANTIATE_TEST_SUITE_P(
    QuicIntegerTests,
    QuicIntegerDecodeTest,
    Values(
        IntegerParams({0, "00", false, 1}),
        IntegerParams({494878333, "9d7f3e7d", false, 4}),
        IntegerParams({15293, "7bbd", false, 2}),
        IntegerParams({37, "25", false, 1}),
        IntegerParams({37, "4025", false, 2}),
        IntegerParams({37, "80000025", false, 4}),
        IntegerParams({37, "C000000000000025", false, 8}),
        IntegerParams({37, "40", true})));

INSTANTIATE_TEST_SUITE_P(
    QuicIntegerEncodeTests,
    QuicIntegerEncodeTest,
    Values(
        IntegerParams({0, "00", false, 1}),
        IntegerParams({151288809941952652, "c2197c5eff14e88c", false}),
        IntegerParams({151288809941952652, "c2197c5eff14e88c", false}),
        IntegerParams({494878333, "9d7f3e7d", false}),
        IntegerParams({15293, "7bbd", false}),
        IntegerParams({37, "25", false}),
        IntegerParams({std::numeric_limits<uint64_t>::max(), "25", true})));

} // namespace quic::test
