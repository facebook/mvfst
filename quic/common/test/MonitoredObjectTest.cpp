/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MonitoredObject.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <functional>

using namespace std;
using namespace quic;
using namespace ::testing;

class MockObjectObserver {
 public:
  MOCK_METHOD(void, accessed, (const string&));
};

TEST(MonitoredObjectTest, TestObserverCalled) {
  InSequence s;
  string x = "abc";
  MockObjectObserver observer;
  auto accessFn =
      std::bind(&MockObjectObserver::accessed, &observer, placeholders::_1);
  MonitoredObject<string> mo(x, accessFn);
  EXPECT_CALL(observer, accessed(x)).Times(1);
  EXPECT_EQ(x, mo->c_str());
  EXPECT_CALL(observer, accessed(x + "d")).Times(1);
  mo->append("d");
  EXPECT_CALL(observer, accessed(x + "de")).Times(1);
  mo->append("e");
}
