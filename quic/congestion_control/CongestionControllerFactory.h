/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicConstants.h>

#include <memory>

namespace quic {
struct CongestionController;
struct QuicConnectionStateBase;

/**
 * Interface to create CongestionController instance.
 * If application supplies the implementation of this factory, the transport
 * calls 'makeCongestionController' for each accepted connection.
 */
class CongestionControllerFactory {
 public:
  virtual ~CongestionControllerFactory() = default;

  virtual std::unique_ptr<CongestionController> makeCongestionController(
      QuicConnectionStateBase& conn,
      CongestionControlType type) = 0;
};

class DefaultCongestionControllerFactory : public CongestionControllerFactory {
 public:
  ~DefaultCongestionControllerFactory() override = default;

  std::unique_ptr<CongestionController> makeCongestionController(
      QuicConnectionStateBase& conn,
      CongestionControlType type) override;
};

} // namespace quic
