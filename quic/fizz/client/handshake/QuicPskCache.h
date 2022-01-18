/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/client/handshake/CachedServerTransportParameters.h>

#include <fizz/client/PskCache.h>
#include <folly/Optional.h>

#include <string>

namespace quic {

struct QuicCachedPsk {
  fizz::client::CachedPsk cachedPsk;
  CachedServerTransportParameters transportParams;
  std::string appParams;
};

class QuicPskCache {
 public:
  virtual ~QuicPskCache() = default;

  virtual folly::Optional<QuicCachedPsk> getPsk(const std::string&) = 0;
  virtual void putPsk(const std::string&, QuicCachedPsk) = 0;
  virtual void removePsk(const std::string&) = 0;
};

/**
 * Basic PSK cache that stores PSKs in a hash map. There is no bound on the size
 * of this cache.
 */
class BasicQuicPskCache : public QuicPskCache {
 public:
  ~BasicQuicPskCache() override = default;

  folly::Optional<QuicCachedPsk> getPsk(const std::string& identity) override {
    auto result = cache_.find(identity);
    if (result != cache_.end()) {
      return result->second;
    }
    return folly::none;
  }

  void putPsk(const std::string& identity, QuicCachedPsk psk) override {
    cache_[identity] = std::move(psk);
  }

  void removePsk(const std::string& identity) override {
    cache_.erase(identity);
  }

 private:
  std::unordered_map<std::string, QuicCachedPsk> cache_;
};

} // namespace quic
