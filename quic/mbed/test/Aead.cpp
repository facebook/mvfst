/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <folly/portability/GTest.h>

#include <fizz/crypto/aead/test/TestUtil.h>
#include <quic/mbed/MbedAead.h>

using namespace folly;
using namespace fizz::test;

// reused test from fizz/crypto/aead/test/EVPCipherTest.cpp
namespace quic::test {

struct CipherParams {
  std::string key;
  std::string iv;
  uint64_t seqNum;
  std::string aad;
  std::string plaintext;
  std::string ciphertext;
  bool valid;
  CipherType cipher;
};

class MbedCipherTest : public ::testing::TestWithParam<CipherParams> {};

std::unique_ptr<Aead> getTestCipher(const CipherParams& params) {
  TrafficKey trafficKey;
  trafficKey.key = toIOBuf(params.key);
  trafficKey.iv = toIOBuf(params.iv);

  std::unique_ptr<Aead> cipher =
      std::make_unique<MbedAead>(params.cipher, std::move(trafficKey));

  return cipher;
}

std::unique_ptr<folly::IOBuf> callEncrypt(
    std::unique_ptr<Aead>& cipher,
    const CipherParams& params,
    std::unique_ptr<IOBuf> plaintext,
    std::unique_ptr<IOBuf> aad = nullptr) {
  if (!aad && !params.aad.empty()) {
    aad = toIOBuf(params.aad);
  }

  auto origLength = plaintext->computeChainDataLength();

  auto out =
      cipher->inplaceEncrypt(std::move(plaintext), aad.get(), params.seqNum);
  bool valid = IOBufEqualTo()(toIOBuf(params.ciphertext), out);

  EXPECT_EQ(valid, params.valid);
  EXPECT_EQ(
      out->computeChainDataLength(), origLength + cipher->getCipherOverhead());
  return out;
}

std::unique_ptr<IOBuf> callDecrypt(
    std::unique_ptr<Aead>& cipher,
    const CipherParams& params,
    std::unique_ptr<IOBuf> ciphertext = nullptr,
    std::unique_ptr<IOBuf> aad = nullptr) {
  if (!ciphertext) {
    ciphertext = toIOBuf(params.ciphertext);
  }
  if (!aad && !params.aad.empty()) {
    aad = toIOBuf(params.aad);
  }
  auto origLength = ciphertext->computeChainDataLength();
  auto out =
      cipher->tryDecrypt(std::move(ciphertext), aad.get(), params.seqNum);
  EXPECT_EQ(out.has_value(), params.valid);
  if (out.has_value()) {
    EXPECT_EQ(
        out.value()->computeChainDataLength(),
        origLength - cipher->getCipherOverhead());
    return std::move(out.value());
  }
  return nullptr;
}

TEST_P(MbedCipherTest, TestEncrypt) {
  auto cipher = getTestCipher(GetParam());
  auto plaintext = toIOBuf(GetParam().plaintext);

  auto out = callEncrypt(cipher, GetParam(), std::move(plaintext));
  EXPECT_EQ(out->headroom(), 0);
}

TEST_P(MbedCipherTest, TestEncryptWithTagRoom) {
  // Behavior should be identical for all, as buffer is unshared with enough
  // room
  auto cipher = getTestCipher(GetParam());
  auto input = toIOBuf(GetParam().plaintext, 0, cipher->getCipherOverhead());
  auto out = callEncrypt(cipher, GetParam(), std::move(input));
  EXPECT_FALSE(out->isChained());
}

TEST_P(MbedCipherTest, TestEncryptReusedCipher) {
  auto cipher = getTestCipher(GetParam());
  auto plaintext = toIOBuf(GetParam().plaintext);
  callEncrypt(cipher, GetParam(), toIOBuf(GetParam().plaintext));
  callEncrypt(cipher, GetParam(), toIOBuf(GetParam().plaintext));
}

TEST_P(MbedCipherTest, TestEncryptReusedCipherWithTagRoom) {
  auto cipher = getTestCipher(GetParam());
  auto params = GetParam();
  callEncrypt(
      cipher,
      params,
      toIOBuf(params.plaintext, 0, cipher->getCipherOverhead()));
  callEncrypt(
      cipher,
      GetParam(),
      toIOBuf(params.plaintext, 0, cipher->getCipherOverhead()));
}

TEST_P(MbedCipherTest, TestDecrypt) {
  auto cipher = getTestCipher(GetParam());
  auto output = toIOBuf(GetParam().ciphertext);
  auto cipherLen = output->length();
  auto out = callDecrypt(cipher, GetParam(), nullptr);
  if (out) {
    EXPECT_FALSE(out->isChained());
    EXPECT_FALSE(out->isShared());
    EXPECT_EQ(out->length(), cipherLen - cipher->getCipherOverhead());
  }
}

TEST_P(MbedCipherTest, TestDecryptReusedCipher) {
  // Same as before
  auto cipher = getTestCipher(GetParam());
  auto params = GetParam();
  callDecrypt(cipher, params, nullptr);
  callDecrypt(cipher, params, nullptr);
}

TEST_P(MbedCipherTest, TestDecryptInputTooSmall) {
  // This should behave identically (the input size check comes early)
  auto cipher = getTestCipher(GetParam());
  auto in = IOBuf::copyBuffer("in");
  auto paramsCopy = GetParam();
  paramsCopy.valid = false;
  callDecrypt(cipher, paramsCopy, std::move(in));
}

TEST_P(MbedCipherTest, TestTryDecrypt) {
  // Should all behave identically, as ciphertext is unshared and contiguous
  auto cipher = getTestCipher(GetParam());
  auto out = cipher->tryDecrypt(
      toIOBuf(GetParam().ciphertext),
      toIOBuf(GetParam().aad).get(),
      GetParam().seqNum);
  if (out) {
    EXPECT_TRUE(GetParam().valid);
    EXPECT_TRUE(IOBufEqualTo()(toIOBuf(GetParam().plaintext), *out));
  } else {
    EXPECT_FALSE(GetParam().valid);
  }
}

// Adapted from draft-thomson-tls-tls13-vectors
INSTANTIATE_TEST_SUITE_P(
    AESGCM128TestVectors,
    MbedCipherTest,
    ::testing::Values(
        CipherParams{
            "87f6c12b1ae8a9b7efafc65af0f5c994",
            "479e25839c19e0476f95a6f5",
            1,
            "",
            "010015",
            "9d4db5ecd768198892531eebac72cf1d477dd0",
            true,
            CipherType::AESGCM128},
        CipherParams{
            "911dc107aa6eccb6706bdcc37e76a07a",
            "11c7fa13e9499ed042b09e57",
            0,
            "",
            "14000020de15cbc8c62d0e6fef73a6d4e70e5c372c2b94fe08ea40d11166a7e6c967ba9c16",
            "56a21739148c898fe807026a179d59202647a3b1e01267a3883cf5f69fd233f63ff12c1c71b4c8f3d6086affb49621f96b842e1d35",
            true,
            CipherType::AESGCM128},
        CipherParams{
            "a0f49e7076cae6eb25ca23a2da0eaf12",
            "3485d33f22128dff91e47062",
            0,
            "",
            "41424344454617",
            "92fdec5c241e994fb7d889e1b61d1db2b9be6777f5a393",
            true,
            CipherType::AESGCM128},
        CipherParams{
            "fda2a4404670808f4937478b8b6e3fe1",
            "b5f3a3fae1cb25c9dcd73993",
            0,
            "",
            "0800001e001c000a00140012001d00170018001901000101010201030104000000000b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d980836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced43120998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d03e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b0603551d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8f8961229ac9187b42b4de100000f000084080400804547d6168f2510c550bd949cd2bc631ff134fa10a827ff69b166a6bd95e249ed0daf571592ebbe9ff13de6b03acc218146781f693b5a692b7319d74fd2e53b6a2df0f6785d624f024a44030ca00b869ae81a532b19e47e525ff4a62c51a5889eb565fee268590d8a3ca3c1bc3bd5404e39720ca2eaee308f4e0700761e986389140000209efee03ebffbc0dc23d26d958744c09e3000477eff7ae3148a50e5670013aaaa16",
            "c1e631f81d2af221ebb6a957f58f3ee266272635e67f99a752f0df08adeb33bab8611e55f33d72cf84382461a8bfe0a659ba2dd1873f6fcc707a9841cefc1fb03526b9ca4fe343e5805e95a5c01e56570638a76a4bc8feb07be879f90568617d905fecd5b1619fb8ec4a6628d1bb2bb224c490ff97a6c0e9acd03604bc3a59d86bdab4e084c1c1450f9c9d2afeb172c07234d739868ebd62de2060a8de989414a82920dacd1cac0c6e72ecd7f4018574ceaca6d29f361bc37ee2888b8e302ca9561a9de9163edfa66badd4894884c7b359bcacae5908051b37952e10a45fe73fda126ebd67575f1bed8a992a89474d7dec1eed327824123a414adb66d5ef7d0836ff98c2cdd7fb0781e192bf0c7568bf7d890a51c332879b5037b212d622412ca48e8323817bd6d746eef683845cec4e3ef64b3a18fcce513ea951f3366693a7ff490d09d08ab1f63e13625a545961599c0d9c7a099d1163cad1b9bcf8e917d766b98853ef6877834f891df16be1fcc9c18ea1882ea3f1f4b64358e1b146cebfb3e02e153fdb73af2693f22c6f593fa475380ba6611740ad20e319a654ac5684775236162e8447ed808861bfbda6e18ec97ae090bf703475cfb90fe20a3c55bef6f5eba6e6a1da6a1996b8bde42180608ca2279def8e8153895cc850db6420561c04b5729cc6883436ea02ee07eb9baee2fb3a9e1bbda8730d6b220576e24df70af6928eb865fee8a1d1c0f1818aca68d5002ae4c65b2f49c9e6e21dcf76784adbd0e887a36832ef85beb10587f16c6ffe60d7451059ec7f1014c3efe19e56aedb5ad31a9f29dc4458cfbf0c7070c175dcad46e1675226b47c071aad3172ebd33e45d741cb91253a01a69ae3cc292bce9c03246ac951e45e97ebf04a9d51fab5cf06d9485cce746b1c077be69ad153f1656ef89fc7d1ed8c3e2da7a2",
            true,
            CipherType::AESGCM128},
        CipherParams{
            "a0f49e7076cbe6eb25ca23a2da0eaf12",
            "3485d33f22128dff91e47062",
            0,
            "",
            "41424344454617",
            "92fdec5c241e994fb7d889e1b61d1db2b9be6777f5a393",
            false,
            CipherType::AESGCM128},
        CipherParams{
            "a0f49e7076cae6eb25ca23a2da0eaf12",
            "3485d33f22128dff91e47062",
            0,
            "",
            "41424344454617",
            "92fdec",
            false,
            CipherType::AESGCM128},
        CipherParams{
            "AD7A2BD03EAC835A6F620FDCB506B345",
            "12153524C0895E81B2C28465",
            0,
            "D609B1F056637A0D46DF998D88E52E00B2C2846512153524C0895E81",
            "08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002",
            "701AFA1CC039C0D765128A665DAB69243899BF7318CCDC81C9931DA17FBE8EDD7D17CB8B4C26FC81E3284F2B7FBA713D4F8D55E7D3F06FD5A13C0C29B9D5B880",
            true,
            CipherType::AESGCM128},
        CipherParams{
            "AD7A2BD03EAC835A6F620FDCB506B345",
            "12153524C0895E81B2C28465",
            0,
            "D609B1F056637A1D46DF998D88E52E00B2C2846512153524C0895E81",
            "08000F101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F303132333435363738393A0002",
            "701AFA1CC039C0D765128A665DAB69243899BF7318CCDC81C9931DA17FBE8EDD7D17CB8B4C26FC81E3284F2B7FBA713D4F8D55E7D3F06FD5A13C0C29B9D5B880",
            false,
            CipherType::AESGCM128}));
} // namespace quic::test
