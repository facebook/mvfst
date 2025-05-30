/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <folly/ObserverContainer.h>
#include <quic/observer/SocketObserverInterface.h>

namespace quic {
class QuicSocketLite;

using SocketObserverContainerBaseT = folly::ObserverContainer<
    SocketObserverInterface,
    QuicSocketLite,
    folly::ObserverContainerBasePolicyDefault<
        SocketObserverInterface::Events /* EventEnum */,
        32 /* BitsetSize (max number of interface events) */>>;

class SocketObserverContainer : public SocketObserverContainerBaseT {
 public:
  using SocketObserverContainerBaseT::SocketObserverContainerBaseT;

  /**
   * Legacy observer for use during transition to folly::ObserverList.
   */
  class LegacyObserver : public Observer {
   public:
    using EventSet = typename Observer::EventSet;
    using EventSetBuilder = typename Observer::EventSetBuilder;
    using Observer::Observer;

    ~LegacyObserver() override = default;

    /**
     * observerAttach() will be invoked when an observer is added.
     *
     * @param socket      Socket where observer was installed.
     */
    virtual void observerAttach(QuicSocketLite* /* socket */) noexcept {}

    /**
     * observerDetach() will be invoked if the observer is uninstalled prior
     * to socket destruction.
     *
     * No further callbacks will be invoked after observerDetach().
     *
     * @param socket      Socket where observer was uninstalled.
     */
    virtual void observerDetach(QuicSocketLite* /* socket */) noexcept {}

    /**
     * destroy() will be invoked when the QuicSocketLite's destructor is
     * invoked.
     *
     * No further callbacks will be invoked after destroy().
     *
     * @param socket      Socket being destroyed.
     */
    virtual void destroy(QuicSocketLite* /* socket */) noexcept {}

   private:
    void attached(QuicSocketLite* obj) noexcept override {
      observerAttach(obj);
    }

    void detached(QuicSocketLite* obj) noexcept override {
      observerDetach(obj);
    }

    void destroyed(QuicSocketLite* obj, DestroyContext* /* ctx */) noexcept
        override {
      destroy(obj);
    }

    void addedToObserverContainer(
        ObserverContainerBase* list) noexcept override {
      CHECK(list->getObject());
    }

    void removedFromObserverContainer(
        ObserverContainerBase* list) noexcept override {
      CHECK(list->getObject());
    }

    void movedToObserverContainer(
        ObserverContainerBase* oldList,
        ObserverContainerBase* newList) noexcept override {
      CHECK(oldList->getObject());
      CHECK(newList->getObject());
    }
  };
};

} // namespace quic
