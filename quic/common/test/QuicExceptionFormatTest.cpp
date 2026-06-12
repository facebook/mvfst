/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/QuicException.h>

#include <fmt/format.h>
#include <folly/portability/GTest.h>

namespace quic::test {

// These assert that fmt-formatting each QUIC error type with "{}" routes
// through quic::toString() (via the fmt::formatter specializations in
// QuicException.h) and produces the same string. Before the formatters
// existed, "{}" on QuicErrorCode/QuicError selected fmt's std::ostream
// fallback into the out-of-line quic::operator<< in libquic_exception.so,
// which SIGSEGV'd on the XR cloud-browser teardown path; and "{}" on the
// scoped enums did not compile at all. These tests are the regression guard
// for both.

TEST(QuicExceptionFormatTest, TransportErrorCode) {
  const auto code = TransportErrorCode::PROTOCOL_VIOLATION;
  EXPECT_EQ(fmt::format("{}", code), toString(code));
}

TEST(QuicExceptionFormatTest, LocalErrorCode) {
  const auto code = LocalErrorCode::CONNECT_FAILED;
  EXPECT_EQ(fmt::format("{}", code), toString(code));
}

TEST(QuicExceptionFormatTest, QuicErrorCodeTransport) {
  const QuicErrorCode code(TransportErrorCode::INTERNAL_ERROR);
  EXPECT_EQ(fmt::format("{}", code), toString(code));
}

TEST(QuicExceptionFormatTest, QuicErrorCodeLocal) {
  const QuicErrorCode code(LocalErrorCode::STREAM_CLOSED);
  EXPECT_EQ(fmt::format("{}", code), toString(code));
}

TEST(QuicExceptionFormatTest, QuicErrorCodeApplication) {
  // The exact flavor that crashed the XR cloud-browser client on connection
  // teardown: an ApplicationErrorCode inside the QuicErrorCode variant.
  const QuicErrorCode code(ApplicationErrorCode{0x2});
  EXPECT_EQ(fmt::format("{}", code), toString(code));
}

TEST(QuicExceptionFormatTest, QuicError) {
  const QuicError error(QuicErrorCode(TransportErrorCode::NO_ERROR), "bye");
  EXPECT_EQ(fmt::format("{}", error), toString(error));
}

} // namespace quic::test
