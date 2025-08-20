/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/StringUtils.h>

#include <gtest/gtest.h>
#include <quic/QuicConstants.h>
#include <string>

using namespace quic;

class StringUtilsTest : public ::testing::Test {};

TEST_F(StringUtilsTest, HexlifyBasicTest) {
  // Test basic string conversion
  std::string input1 = "0123";
  std::string expected1 = "30313233";
  EXPECT_EQ(expected1, hexlify(input1));

  // Test string with null bytes and high-value bytes
  std::string input2 = "abcdefg";
  input2[1] = 0; // null byte
  input2[3] = 0xff; // high value byte
  input2[5] = 0xb6; // another high value byte
  std::string expected2 = "610063ff65b667";
  EXPECT_EQ(expected2, hexlify(input2));
}

TEST_F(StringUtilsTest, HexlifyCommonStrings) {
  // Test common string
  EXPECT_EQ("666f6f626172", hexlify("foobar"));

  // Test empty string
  EXPECT_EQ("", hexlify(""));

  // Test single character
  EXPECT_EQ("61", hexlify("a"));

  // Test string with spaces
  EXPECT_EQ("68656c6c6f20776f726c64", hexlify("hello world"));
}

TEST_F(StringUtilsTest, HexlifyBinaryData) {
  // Test binary data with known hex values
  std::string binary = "\x01\x02\x03\x04";
  EXPECT_EQ("01020304", hexlify(binary));

  // Test all possible byte values (0-255)
  std::string allBytes;
  for (int i = 0; i < 256; ++i) {
    allBytes += static_cast<char>(i);
  }

  std::string result = hexlify(allBytes);
  EXPECT_EQ(512, result.length()); // Each byte becomes 2 hex chars

  // Verify first few bytes
  EXPECT_EQ("000102", result.substr(0, 6));
  // Verify last few bytes
  EXPECT_EQ("fdfeff", result.substr(result.length() - 6));
}

TEST_F(StringUtilsTest, UnhexlifyBasicTest) {
  // Test basic hex string conversion
  std::string input1 = "30313233";
  auto result1 = unhexlify(input1);
  ASSERT_TRUE(result1.has_value());
  EXPECT_EQ("0123", result1.value());

  // Test hex string with null bytes and high-value bytes
  std::string input2 = "610063ff65b667";
  auto result2 = unhexlify(input2);
  ASSERT_TRUE(result2.has_value());
  EXPECT_EQ(7, result2.value().size());
  EXPECT_EQ('a', result2.value()[0]);
  EXPECT_EQ(0, result2.value()[1]);
  EXPECT_EQ('c', result2.value()[2]);
  EXPECT_EQ(static_cast<char>(0xff), result2.value()[3]);
  EXPECT_EQ('e', result2.value()[4]);
  EXPECT_EQ(static_cast<char>(0xb6), result2.value()[5]);
  EXPECT_EQ('g', result2.value()[6]);
}

TEST_F(StringUtilsTest, UnhexlifyCommonStrings) {
  // Test common string
  auto result1 = unhexlify("666f6f626172");
  ASSERT_TRUE(result1.has_value());
  EXPECT_EQ("foobar", result1.value());

  // Test empty string
  auto result2 = unhexlify("");
  ASSERT_TRUE(result2.has_value());
  EXPECT_EQ("", result2.value());

  // Test single byte
  auto result3 = unhexlify("61");
  ASSERT_TRUE(result3.has_value());
  EXPECT_EQ("a", result3.value());

  // Test string with null byte
  auto result4 = unhexlify("666f6f00626172");
  ASSERT_TRUE(result4.has_value());
  EXPECT_EQ(std::string("foo\0bar", 7), result4.value());
}

TEST_F(StringUtilsTest, UnhexlifyCaseInsensitive) {
  // Test uppercase hex
  auto result1 = unhexlify("41424344");
  ASSERT_TRUE(result1.has_value());
  EXPECT_EQ("ABCD", result1.value());

  // Test lowercase hex
  auto result2 = unhexlify("61626364");
  ASSERT_TRUE(result2.has_value());
  EXPECT_EQ("abcd", result2.value());

  // Test mixed case hex
  auto result3 = unhexlify("4142636466474849");
  ASSERT_TRUE(result3.has_value());
  EXPECT_EQ("ABcdfGHI", result3.value());
}

TEST_F(StringUtilsTest, UnhexlifyBinaryData) {
  // Test binary data conversion
  auto result1 = unhexlify("01020304");
  ASSERT_TRUE(result1.has_value());
  EXPECT_EQ(std::string("\x01\x02\x03\x04", 4), result1.value());

  // Test all possible byte values
  std::string hexAllBytes;
  for (int i = 0; i < 256; ++i) {
    char hex[3];
    snprintf(hex, sizeof(hex), "%02x", i);
    hexAllBytes += hex;
  }

  auto result2 = unhexlify(hexAllBytes);
  ASSERT_TRUE(result2.has_value());
  EXPECT_EQ(256, result2.value().length());

  // Verify first few bytes
  EXPECT_EQ(0, static_cast<unsigned char>(result2.value()[0]));
  EXPECT_EQ(1, static_cast<unsigned char>(result2.value()[1]));
  EXPECT_EQ(2, static_cast<unsigned char>(result2.value()[2]));

  // Verify last few bytes
  EXPECT_EQ(253, static_cast<unsigned char>(result2.value()[253]));
  EXPECT_EQ(254, static_cast<unsigned char>(result2.value()[254]));
  EXPECT_EQ(255, static_cast<unsigned char>(result2.value()[255]));
}

TEST_F(StringUtilsTest, UnhexlifyErrorCases) {
  // Test odd length string (should fail)
  auto result1 = unhexlify("x");
  EXPECT_FALSE(result1.has_value());

  auto result2 = unhexlify("123");
  EXPECT_FALSE(result2.has_value());

  // Test invalid hex characters (should fail)
  auto result3 = unhexlify("xy");
  EXPECT_FALSE(result3.has_value());

  auto result4 = unhexlify("1g");
  EXPECT_FALSE(result4.has_value());

  auto result5 = unhexlify("zz");
  EXPECT_FALSE(result5.has_value());

  // Test string with spaces (should fail)
  auto result6 = unhexlify("12 34");
  EXPECT_FALSE(result6.has_value());

  // Test string with punctuation (should fail)
  auto result7 = unhexlify("12,34");
  EXPECT_FALSE(result7.has_value());

  // Test string with mixed valid/invalid chars
  auto result8 = unhexlify("12zz34");
  EXPECT_FALSE(result8.has_value());
}

TEST_F(StringUtilsTest, RoundTripConversion) {
  // Test that hexlify -> unhexlify gives back original string
  std::vector<std::string> testStrings = {
      "",
      "a",
      "hello",
      "hello world",
      "foobar",
      std::string("foo\0bar", 7), // string with null byte
      std::string("\x01\x02\x03\x04", 4), // binary data
  };

  for (const auto& original : testStrings) {
    std::string hexed = hexlify(original);
    auto unhexed = unhexlify(hexed);
    ASSERT_TRUE(unhexed.has_value()) << "Failed to unhexlify: " << hexed;
    EXPECT_EQ(original, unhexed.value())
        << "Round trip failed for: " << original;
  }
}

TEST_F(StringUtilsTest, RoundTripBinaryData) {
  // Test round trip with all possible byte values
  std::string allBytes;
  for (int i = 0; i < 256; ++i) {
    allBytes += static_cast<char>(i);
  }

  std::string hexed = hexlify(allBytes);
  auto unhexed = unhexlify(hexed);
  ASSERT_TRUE(unhexed.has_value());
  EXPECT_EQ(allBytes, unhexed.value());
}

TEST_F(StringUtilsTest, PerformanceBasicTest) {
  // Test with a reasonably sized string to ensure no obvious performance issues
  std::string largeString(10000, 'x'); // 10KB string

  std::string hexed = hexlify(largeString);
  EXPECT_EQ(20000, hexed.length()); // Should be twice the original size

  auto unhexed = unhexlify(hexed);
  ASSERT_TRUE(unhexed.has_value());
  EXPECT_EQ(largeString, unhexed.value());
}

TEST_F(StringUtilsTest, EdgeCaseInputs) {
  // Test with UTF-8 encoded strings (they should be treated as raw bytes)
  std::string utf8String = "héllo wørld";
  std::string hexed = hexlify(utf8String);
  auto unhexed = unhexlify(hexed);
  ASSERT_TRUE(unhexed.has_value());
  EXPECT_EQ(utf8String, unhexed.value());

  // Test with string containing all printable ASCII
  std::string asciiString;
  for (int i = 32; i < 127; ++i) { // printable ASCII range
    asciiString += static_cast<char>(i);
  }

  std::string hexedAscii = hexlify(asciiString);
  auto unhexedAscii = unhexlify(hexedAscii);
  ASSERT_TRUE(unhexedAscii.has_value());
  EXPECT_EQ(asciiString, unhexedAscii.value());
}

TEST_F(StringUtilsTest, ErrorHandlingTypes) {
  // Test odd length error returns proper QuicError with INTERNAL_ERROR
  auto result1 = unhexlify("123");
  ASSERT_FALSE(result1.has_value());
  auto error1 = result1.error();
  EXPECT_EQ(QuicErrorCode(TransportErrorCode::INTERNAL_ERROR), error1.code);
  EXPECT_EQ("Input string must have even length", error1.message);

  // Test invalid hex character error returns proper QuicError with
  // INTERNAL_ERROR
  auto result2 = unhexlify("1g");
  ASSERT_FALSE(result2.has_value());
  auto error2 = result2.error();
  EXPECT_EQ(QuicErrorCode(TransportErrorCode::INTERNAL_ERROR), error2.code);
  EXPECT_EQ("Invalid hex character in input string", error2.message);
}
