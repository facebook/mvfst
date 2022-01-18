/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/protocol/CertificateVerifier.h>

namespace quic::test {

class TestCertificateVerifier : public fizz::CertificateVerifier {
 public:
  ~TestCertificateVerifier() override = default;

  void verify(const std::vector<std::shared_ptr<const fizz::PeerCert>>&)
      const override {
    return;
  }

  [[nodiscard]] std::vector<fizz::Extension> getCertificateRequestExtensions()
      const override {
    return std::vector<fizz::Extension>();
  }
};

inline std::unique_ptr<fizz::CertificateVerifier>
createTestCertificateVerifier() {
  return std::make_unique<TestCertificateVerifier>();
}

} // namespace quic::test
