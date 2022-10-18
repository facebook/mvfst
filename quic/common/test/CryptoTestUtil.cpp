/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// Copied from
// https://github.com/facebookincubator/fizz/blob/master/fizz/crypto/test/TestUtil.cpp
#include <fizz/crypto/test/TestUtil.h>

#include <folly/String.h>
#include <folly/ssl/OpenSSLCertUtils.h>
#include <sodium/randombytes.h>

using namespace folly;
using namespace folly::ssl;

namespace fizz {
namespace test {

EvpPkeyUniquePtr getPrivateKey(StringPiece key) {
  BioUniquePtr bio(BIO_new(BIO_s_mem()));
  CHECK(bio);
  CHECK_EQ(BIO_write(bio.get(), key.data(), key.size()), key.size());
  EvpPkeyUniquePtr pkey(
      PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  CHECK(pkey);
  return pkey;
}

EvpPkeyUniquePtr getPublicKey(StringPiece key) {
  BioUniquePtr bio(BIO_new(BIO_s_mem()));
  CHECK(bio);
  CHECK_EQ(BIO_write(bio.get(), key.data(), key.size()), key.size());
  EvpPkeyUniquePtr pkey(
      PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  CHECK(pkey);
  return pkey;
}

// Converts the hex encoded string to an IOBuf.
std::unique_ptr<folly::IOBuf> toIOBuf(folly::StringPiece hexData) {
  std::string out;
  CHECK(folly::unhexlify(hexData, out));
  return folly::IOBuf::copyBuffer(out);
}

folly::ssl::X509UniquePtr getCert(folly::StringPiece cert) {
  BioUniquePtr bio(BIO_new(BIO_s_mem()));
  CHECK(bio);
  CHECK_EQ(BIO_write(bio.get(), cert.data(), cert.size()), cert.size());
  X509UniquePtr x509(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
  CHECK(x509);
  return x509;
}

std::unique_ptr<folly::IOBuf> getCertData(folly::StringPiece cert) {
  return OpenSSLCertUtils::derEncode(*getCert(cert));
}

static struct randombytes_implementation mockRandom = {
    []() { return "test"; }, // implementation_name
    []() { return (uint32_t)0x44444444; }, // random
    nullptr, // stir
    nullptr, // uniform
    [](void* const buf, const size_t size) { memset(buf, 0x44, size); }, // buf
    nullptr}; // close

void useMockRandom() {
  randombytes_set_implementation(&mockRandom);
}
} // namespace test
} // namespace fizz
