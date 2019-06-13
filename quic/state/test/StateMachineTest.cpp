/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <quic/state/StateMachine.h>

using namespace testing;

namespace quic {

struct State1 {};
struct State2 {};
struct State3 {};

struct Event1 {};
struct Event2 {};

struct ConnectionState {
  boost::variant<State1, State2, State3> state;
  bool visitedState1Event1{false};
  bool visitedState1Event2{false};
  bool visitedState2Event2{false};
};

struct InvalidHandlerException : public std::runtime_error {
  explicit InvalidHandlerException(std::string msg)
      : std::runtime_error(std::move(msg)) {}
};

void ThrowExceptionHandler(const ConnectionState&) {
  throw InvalidHandlerException("invalid state");
}

struct TestMachine {
  using StateData = ConnectionState;
  using UserData = ConnectionState;
  static auto constexpr InvalidEventHandler = &ThrowExceptionHandler;
};

QUIC_DECLARE_STATE_HANDLER(TestMachine, State1, Event1, State2);
QUIC_DECLARE_STATE_HANDLER(TestMachine, State1, Event2, State3);
QUIC_DECLARE_STATE_HANDLER(TestMachine, State2, Event2, State1, State3);

// The handlers
void Handler<TestMachine, State1, Event1>::handle(
    ConnectionState& connState,
    Event1&& /*event*/,
    TestMachine::UserData&) {
  connState.visitedState1Event1 = true;
  transit<State2>(connState);
}

void Handler<TestMachine, State1, Event2>::handle(
    ConnectionState& connState,
    Event2&& /*event*/,
    TestMachine::UserData&) {
  connState.visitedState1Event2 = true;
  transit<State3>(connState);
  // transit<State1>(connState); This will fail to compile because it
  // is an invalid state transition.
}

void Handler<TestMachine, State2, Event2>::handle(
    ConnectionState& connState,
    Event2&& /*event*/,
    TestMachine::UserData&) {
  connState.visitedState2Event2 = true;
  transit<State3>(connState);
}

template <typename T>
struct ConnectionStateT {
  boost::variant<State1, State2, State3> state;
  bool visitedState1Event1{false};
  bool visitedState1Event2{false};
  bool visitedState2Event2{false};
};

template <typename T>
struct TestMachineT {
  using StateData = ConnectionStateT<T>;
  using UserData = ConnectionStateT<T>;
  static void InvalidEventHandler(ConnectionStateT<T>& /*s*/) {
    throw InvalidHandlerException("invalid state in template machine");
  }
};

QUIC_DECLARE_STATE_HANDLER_T(State1, Event1, State2);
QUIC_DECLARE_STATE_HANDLER_T(State1, Event2, State3);
QUIC_DECLARE_STATE_HANDLER_T(State2, Event2, State3);

template <typename Machine>
void Handler<Machine, State1, Event1>::handle(
    typename Machine::StateData& s,
    Event1&&,
    typename Machine::UserData&) {
  s.visitedState1Event1 = true;
  transit<State2>(s);
}

template <typename Machine>
void Handler<Machine, State1, Event2>::handle(
    typename Machine::StateData& s,
    Event2&&,
    typename Machine::UserData&) {
  s.visitedState1Event2 = true;
  transit<State3>(s);
}

template <typename Machine>
void Handler<Machine, State2, Event2>::handle(
    typename Machine::StateData& s,
    Event2&&,
    typename Machine::UserData&) {
  s.visitedState2Event2 = true;
  transit<State3>(s);
}

namespace test {

class StateMachineTest : public Test {
 public:
  ConnectionState state;
  ConnectionStateT<int> stateT;
};

TEST_F(StateMachineTest, TestTransitions) {
  state.state = State1();
  invokeHandler<TestMachine>(state, Event1(), state);
  EXPECT_TRUE(state.visitedState1Event1);
  EXPECT_FALSE(state.visitedState1Event2);
  EXPECT_FALSE(state.visitedState2Event2);

  // check that the state is correct.
  boost::get<State2>(state.state);

  invokeHandler<TestMachine>(state, Event2(), state);

  EXPECT_TRUE(state.visitedState1Event1);
  EXPECT_FALSE(state.visitedState1Event2);
  EXPECT_TRUE(state.visitedState2Event2);

  boost::get<State3>(state.state);
}

TEST_F(StateMachineTest, TestInvalid) {
  state.state = State2();
  EXPECT_THROW(
      invokeHandler<TestMachine>(state, Event1(), state),
      InvalidHandlerException);
}

TEST_F(StateMachineTest, TestTemplateTransitions) {
  stateT.state = State1();
  invokeHandler<TestMachineT<int>>(stateT, Event1(), stateT);
  EXPECT_TRUE(stateT.visitedState1Event1);
  EXPECT_FALSE(stateT.visitedState1Event2);
  EXPECT_FALSE(stateT.visitedState2Event2);

  boost::get<State2>(stateT.state);

  invokeHandler<TestMachineT<int>>(stateT, Event2(), stateT);

  EXPECT_TRUE(stateT.visitedState1Event1);
  EXPECT_FALSE(stateT.visitedState1Event2);
  EXPECT_TRUE(stateT.visitedState2Event2);

  boost::get<State3>(stateT.state);
}

TEST_F(StateMachineTest, TestTemplateInvalid) {
  stateT.state = State2();
  EXPECT_THROW(
      invokeHandler<TestMachineT<int>>(stateT, Event1(), stateT),
      InvalidHandlerException);
}
} // namespace test
} // namespace quic
