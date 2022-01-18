/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

namespace quic {

class QuicTransportBase;
class QuicServerWorker;

/**
 * Observer of events related to connection acceptance.
 *
 * This observer can be combined with QuicSocket::Observer and other
 * observers to enable instrumentation to be installed when a connection is
 * accepted. For instance, a sampling algorithm can be executed in accept() to
 * sample and install instrumentation on a subset of connections.
 *
 * TODO(bschlinker): Add ready() to have parity with wangle::AcceptObserver.
 */
class AcceptObserver {
 public:
  virtual ~AcceptObserver() = default;

  /**
   * accept() is invoked after a connection has been accepted, which occurs
   * after a QuicServerTransport is instantiated by QuicServerTransportFactory,
   * configured, and QuicServerTransport::accept() is called.
   *
   * @param transport   Transport of accepted connection.
   */
  virtual void accept(QuicTransportBase* transport) noexcept = 0;

  /**
   * acceptorDestroy() is invoked when the worker (acceptor) is destroyed.
   *
   * No further events will be invoked after acceptorDestroy().
   *
   * @param worker      Worker (acceptor) that was destroyed.
   */
  virtual void acceptorDestroy(QuicServerWorker* worker) noexcept = 0;

  /**
   * observerAttached() is invoked when the observer is installed.
   *
   * @param worker      Worker (acceptor) that the observer is attached to.
   */
  virtual void observerAttach(QuicServerWorker* worker) noexcept = 0;

  /**
   * observerDetached() is invoked if the observer is uninstalled prior to
   * worker (acceptor) destruction.
   *
   * No further events will be invoked after observerDetached().
   *
   * @param worker      Worker (acceptor) that the observer was removed from.
   */
  virtual void observerDetach(QuicServerWorker* worker) noexcept = 0;
};

} // namespace quic
