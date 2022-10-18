/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Copied from
// https://github.com/facebookincubator/fizz/blob/master/fizz/crypto/aead/test/TestUtil.cpp
#include <fizz/crypto/aead/test/TestUtil.h>

#include <fizz/crypto/aead/IOBufUtil.h>

using namespace folly;

namespace fizz {
namespace test {

std::unique_ptr<folly::IOBuf> defaultCreator(size_t len, size_t) {
  return IOBuf::create(len);
}

// Converts the hex encoded string to an IOBuf.
std::unique_ptr<folly::IOBuf>
toIOBuf(std::string hexData, size_t headroom, size_t tailroom) {
  std::string out;
  CHECK(folly::unhexlify(hexData, out));
  return folly::IOBuf::copyBuffer(out, headroom, tailroom);
}

std::unique_ptr<IOBuf>
chunkIOBuf(std::unique_ptr<IOBuf> input, size_t chunks, BufCreator creator) {
  if (!creator) {
    creator = defaultCreator;
  }
  // create IOBuf chunks
  size_t inputLen = input->computeChainDataLength();
  size_t chunkLen = floor((double)inputLen / (double)chunks);
  std::unique_ptr<IOBuf> chunked;

  for (size_t i = 0; i < chunks - 1; ++i) {
    auto buf = creator(chunkLen, i);
    buf->append(chunkLen);
    if (!chunked) {
      chunked = std::move(buf);
    } else {
      chunked->prependChain(std::move(buf));
    }
  }

  size_t remainLen = inputLen - (chunks - 1) * chunkLen;
  auto remain = creator(remainLen, chunks - 1);
  remain->append(remainLen);
  chunked->prependChain(std::move(remain));

  transformBuffer(
      *input, *chunked, [](uint8_t* out, const uint8_t* in, size_t len) {
        memcpy(out, in, len);
      });

  CHECK_EQ(chunks, chunked->countChainElements());
  return chunked;
}
} // namespace test
} // namespace fizz
