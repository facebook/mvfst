/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/api/test/Mocks.h>
#include <quic/api/test/QuicTypedTransportTestUtil.h>
#include <quic/fizz/client/test/QuicClientTransportTestUtil.h>
#include <quic/server/test/QuicServerTransportTestUtil.h>

using namespace folly;
using namespace folly::test;
using namespace testing;

namespace {

using TransportTypes = testing::Types<
    quic::test::QuicClientTransportAfterStartTestBase,
    quic::test::QuicServerTransportTestBase>;

class TransportTypeNames {
 public:
  template <typename T>
  static std::string GetName(int) {
    // we have to remove "::" from the string that we return here,
    // or gtest will silently refuse to run these tests!
    auto str = folly::demangle(typeid(T)).toStdString();
    if (str.find_last_of("::") != str.npos) {
      return str.substr(str.find_last_of("::") + 1);
    }
    return str;
  }
};

} // namespace

namespace quic::test {

template <typename T>
class QuicTypedTransportTest : public virtual testing::Test,
                               public QuicTypedTransportTestBase<T> {
 public:
  void SetUp() override {
    // trigger setup of the underlying transport
    QuicTypedTransportTestBase<T>::SetUp();
  }
};

TYPED_TEST_SUITE(
    QuicTypedTransportTest,
    ::TransportTypes,
    ::TransportTypeNames);

TYPED_TEST(QuicTypedTransportTest, ObserverAttach) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, observerAttach(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));
  EXPECT_CALL(*observer, observerDetach(transport));
  EXPECT_TRUE(transport->removeObserver(observer.get()));
  Mock::VerifyAndClearExpectations(observer.get());
  EXPECT_THAT(transport->getObservers(), IsEmpty());
}

TYPED_TEST(QuicTypedTransportTest, ObserverCloseNoErrorThenDestroyTransport) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, observerAttach(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const std::pair<QuicErrorCode, std::string> defaultError = std::make_pair(
      GenericApplicationErrorCode::NO_ERROR,
      toString(GenericApplicationErrorCode::NO_ERROR));
  EXPECT_CALL(
      *observer,
      close(
          transport,
          folly::Optional<std::pair<QuicErrorCode, std::string>>(
              defaultError)));
  transport->close(folly::none);
  Mock::VerifyAndClearExpectations(observer.get());
  InSequence s;
  EXPECT_CALL(*observer, destroy(transport));
  this->destroyTransport();
  Mock::VerifyAndClearExpectations(observer.get());
}

TYPED_TEST(QuicTypedTransportTest, ObserverCloseWithErrorThenDestroyTransport) {
  auto transport = this->getTransport();
  auto observer = std::make_unique<StrictMock<MockObserver>>();

  EXPECT_CALL(*observer, observerAttach(transport));
  transport->addObserver(observer.get());
  EXPECT_THAT(transport->getObservers(), UnorderedElementsAre(observer.get()));

  const auto testError = std::make_pair(
      QuicErrorCode(LocalErrorCode::CONNECTION_RESET),
      std::string("testError"));
  EXPECT_CALL(
      *observer,
      close(
          transport,
          folly::Optional<std::pair<QuicErrorCode, std::string>>(testError)));
  transport->close(testError);
  Mock::VerifyAndClearExpectations(observer.get());
  InSequence s;
  EXPECT_CALL(*observer, destroy(transport));
  this->destroyTransport();
  Mock::VerifyAndClearExpectations(observer.get());
}

} // namespace quic::test
