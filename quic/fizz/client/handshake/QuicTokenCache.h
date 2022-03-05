/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <string>
#include <unordered_map>

#include <folly/Optional.h>
#include <folly/String.h>

namespace quic {

class QuicTokenCache {
 public:
  virtual ~QuicTokenCache() = default;

  [[nodiscard]] virtual folly::Optional<std::string> getToken(
      const std::string& hostname) = 0;

  virtual void putToken(const std::string& hostname, std::string token) = 0;

  virtual void removeToken(const std::string& hostname) = 0;
};

class BasicQuicTokenCache : public QuicTokenCache {
 public:
  ~BasicQuicTokenCache() override = default;

  folly::Optional<std::string> getToken(const std::string& hostname) override {
    auto res = cache_.find(hostname);
    if (res != cache_.end()) {
      return res->second;
    }
    return folly::none;
  }

  void putToken(const std::string& hostname, std::string token) override {
    cache_[hostname] = std::move(token);
  }

  void removeToken(const std::string& hostname) override {
    cache_.erase(hostname);
  }

 private:
  std::unordered_map<std::string, std::string> cache_;
};
} // namespace quic
