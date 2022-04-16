/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/QuicException.h>
#include <quic/common/SmallVec.h>
#include <quic/d6d/Types.h>
#include <quic/observer/SocketObserverInterface.h>
#include <quic/state/AckEvent.h>
#include <quic/state/OutstandingPacket.h>
#include <quic/state/QuicStreamUtilities.h>

namespace folly {
class EventBase;
}

namespace quic {
class QuicSocket;

/**
 * ===== Observer API =====
 */

/**
 * Observer of socket events.
 */
class Observer : public SocketObserverInterface {
 public:
  /**
   * Observer configuration.
   *
   * Specifies events observer wants to receive.
   */
  struct Config {
    virtual ~Config() = default;

    // following flags enable support for various callbacks.
    // observer and socket lifecycle callbacks are always enabled.
    bool evbEvents{false};
    bool packetsWrittenEvents{false};
    bool appRateLimitedEvents{false};
    bool lossEvents{false};
    bool spuriousLossEvents{false};
    bool pmtuEvents{false};
    bool rttSamples{false};
    bool knobFrameEvents{false};
    bool streamEvents{false};
    bool acksProcessedEvents{false};

    virtual void enableAllEvents() {
      evbEvents = true;
      packetsWrittenEvents = true;
      appRateLimitedEvents = true;
      rttSamples = true;
      lossEvents = true;
      spuriousLossEvents = true;
      pmtuEvents = true;
      knobFrameEvents = true;
      streamEvents = true;
      acksProcessedEvents = true;
    }

    /**
     * Returns a config where all events are enabled.
     */
    static Config getConfigAllEventsEnabled() {
      Config config = {};
      config.enableAllEvents();
      return config;
    }
  };

  /**
   * Constructor for observer, uses default config (all callbacks disabled).
   */
  Observer() : Observer(Config()) {}

  /**
   * Constructor for observer.
   *
   * @param config      Config, defaults to auxilary instrumentaton disabled.
   */
  explicit Observer(const Config& observerConfig)
      : observerConfig_(observerConfig) {}

  ~Observer() override = default;

  /**
   * Returns observers configuration.
   */
  const Config& getConfig() {
    return observerConfig_;
  }

  /**
   * observerAttach() will be invoked when an observer is added.
   *
   * @param socket      Socket where observer was installed.
   */
  virtual void observerAttach(QuicSocket* /* socket */) noexcept {}

  /**
   * observerDetach() will be invoked if the observer is uninstalled prior
   * to socket destruction.
   *
   * No further callbacks will be invoked after observerDetach().
   *
   * @param socket      Socket where observer was uninstalled.
   */
  virtual void observerDetach(QuicSocket* /* socket */) noexcept {}

  /**
   * destroy() will be invoked when the QuicSocket's destructor is invoked.
   *
   * No further callbacks will be invoked after destroy().
   *
   * @param socket      Socket being destroyed.
   */
  virtual void destroy(QuicSocket* /* socket */) noexcept {}

 protected:
  // observer configuration; cannot be changed post instantiation
  const Config observerConfig_;
};

// Container for instrumentation observers.
// Avoids heap allocation for up to 2 observers being installed.
using ObserverVec = SmallVec<Observer*, 2>;

} // namespace quic
