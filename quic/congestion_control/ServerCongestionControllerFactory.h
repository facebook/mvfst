/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/congestion_control/CongestionControllerFactory.h>

namespace quic {

/**
 * Interface to create CongestionController instances on *server*-side
 * applications only.
 *
 * This interface allows for the use of some algorithms that should not be used
 * on client applications, such as CCP. The separation prevents client
 * applications from depending upon these unused algorithm implementations.
 *
 * To use this interface instead of the default, pass a new instance of this
 * class to QuicServer::setCongestionControllerFactory.
 */
class ServerCongestionControllerFactory : public CongestionControllerFactory {
 public:
  ~ServerCongestionControllerFactory() override = default;

  std::unique_ptr<CongestionController> makeCongestionController(
      QuicConnectionStateBase& conn,
      CongestionControlType type) override;
};

} // namespace quic
