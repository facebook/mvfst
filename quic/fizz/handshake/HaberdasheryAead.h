/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <fizz/crypto/aead/Aead.h>
#include <quic/handshake/Aead.h>

#include <memory>
#include <string_view>
#include <vector>

namespace quic {

/**
 * Packet protection backed by haberdashery's AES-128-GCM assembly, using the
 * implementation tuned for the CPU when there is one. Other ciphers, and CPUs
 * without a supported implementation, use FizzAead.
 */
class HaberdasheryAead {
 public:
  static std::unique_ptr<Aead> wrap(std::unique_ptr<fizz::Aead> fizzAead);

  // The implementations that this CPU supports, in the order wrap tries them.
  static std::vector<std::string_view> supportedImplementations();

  // Uses the named implementation. Returns null when the name is not among
  // supportedImplementations or the key is not AES-128-GCM.
  static std::unique_ptr<Aead> wrapWith(
      std::string_view name,
      const fizz::Aead& fizzAead);
};

} // namespace quic
