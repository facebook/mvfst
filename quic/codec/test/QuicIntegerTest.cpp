/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/Expected.h>
#include <folly/Optional.h>
#include <folly/String.h>
#include <folly/io/IOBuf.h>
#include <folly/portability/GTest.h>

#include <quic/QuicException.h>
#include <quic/codec/QuicInteger.h>

using namespace testing;
using namespace folly;

namespace quic {
namespace test {

struct IntegerParams {
  uint64_t decoded;
  std::string hexEncoded;
  bool error{false};
  uint8_t encodedLength{8};
};

class QuicIntegerDecodeTest : public TestWithParam<IntegerParams> {};
class QuicIntegerEncodeTest : public TestWithParam<IntegerParams> {};

TEST_P(QuicIntegerDecodeTest, DecodeTrim) {
  std::string encodedBytes = folly::unhexlify(GetParam().hexEncoded);

  for (int atMost = 0; atMost <= GetParam().encodedLength; atMost++) {
    auto wrappedEncoded = IOBuf::copyBuffer(encodedBytes);
    wrappedEncoded->trimEnd(std::min(
        (unsigned long)(wrappedEncoded->computeChainDataLength()),
        (unsigned long)(GetParam().encodedLength - atMost)));
    folly::io::Cursor cursor(wrappedEncoded.get());
    auto originalLength = cursor.length();
    auto decodedValue = decodeQuicInteger(cursor);
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
  std::string encodedBytes = folly::unhexlify(GetParam().hexEncoded);
  auto wrappedEncoded = IOBuf::copyBuffer(encodedBytes);

  for (int atMost = 0; atMost <= GetParam().encodedLength; atMost++) {
    folly::io::Cursor cursor(wrappedEncoded.get());
    auto originalLength = cursor.length();
    auto decodedValue = decodeQuicInteger(cursor, atMost);
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
  auto encodedValue = folly::hexlify(queue->moveToFbString().toStdString());
  LOG(INFO) << "encoded=" << encodedValue;
  LOG(INFO) << "expected=" << GetParam().hexEncoded;

  EXPECT_EQ(encodedValue, GetParam().hexEncoded);
  EXPECT_EQ(*written, encodedValue.size() / 2);
}

TEST_P(QuicIntegerEncodeTest, GetSize) {
  auto size = getQuicIntegerSize(GetParam().decoded);
  if (GetParam().error) {
    EXPECT_TRUE(size.hasError());
    EXPECT_EQ(size.error(), TransportErrorCode::INTERNAL_ERROR);
    return;
  }
  EXPECT_EQ(*size, GetParam().hexEncoded.size() / 2);
}

TEST_F(QuicIntegerEncodeTest, ForceFourBytes) {
  auto queue = folly::IOBuf::create(0);
  BufAppender appender(queue.get(), 10);
  auto appendOp = [&](auto val) { appender.writeBE(val); };
  EXPECT_EQ(4, *encodeQuicInteger(37, appendOp, 4));
  auto encodedValue = folly::hexlify(queue->moveToFbString().toStdString());
  EXPECT_EQ("80000025", encodedValue);
}

TEST_F(QuicIntegerEncodeTest, ForceEightBytes) {
  auto queue = folly::IOBuf::create(0);
  BufAppender appender(queue.get(), 10);
  auto appendOp = [&](auto val) { appender.writeBE(val); };
  EXPECT_EQ(8, *encodeQuicInteger(37, appendOp, 8));
  auto encodedValue = folly::hexlify(queue->moveToFbString().toStdString());
  EXPECT_EQ("c000000000000025", encodedValue);
}

TEST_F(QuicIntegerEncodeTest, ForceWrongBytes) {
  auto queue = folly::IOBuf::create(0);
  BufAppender appender(queue.get(), 10);
  auto appendOp = [&](auto val) { appender.writeBE(val); };
  EXPECT_DEATH(encodeQuicInteger(15293, appendOp, 1), "");
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

} // namespace test
} // namespace quic
