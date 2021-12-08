// (c) Facebook, Inc. and its affiliates. Confidential and proprietary.

// #include <folly/portability/GMock.h>
// #include <folly/portability/GTest.h>

#include <quic/common/test/TestUtils.h>
#include <quic/state/StateData.h>
#include "quic/api/QuicTransportBase.h"

namespace quic::test {

template <typename QuicTransportTestClass>
class QuicTypedTransportTestBase : protected QuicTransportTestClass {
 public:
  using QuicTransportTestClass::QuicTransportTestClass;

  ~QuicTypedTransportTestBase() override = default;

  void SetUp() override {
    QuicTransportTestClass::SetUp();
  }

  QuicTransportBase* getTransport() {
    return QuicTransportTestClass::getTransport();
  }

  const QuicConnectionStateBase& getConn() {
    return QuicTransportTestClass::getConn();
  }

  QuicConnectionStateBase& getNonConstConn() {
    return QuicTransportTestClass::getNonConstConn();
  }
};

} // namespace quic::test
