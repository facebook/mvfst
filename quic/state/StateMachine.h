/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#pragma once

#include <boost/variant.hpp>
#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/get.hpp>
#include <boost/variant/static_visitor.hpp>
#include <folly/Overload.h>
#include <exception>

namespace quic {

/**
 * This provides a Framework for building State machines in QUIC with 2
 * properties, especially if your state machines have many paths depending on
 * input data. It provides the ability to restrict the set of transitions from
 * StateA -> StateB.
 *
 * To create a new State machine:
 * 1. Create a StateData type which will be modified by the state machine
 * 2. Create a Machine type with an alias of StateData
 *    struct Machine {
 *       using StateData = StateDataType;
 *       using UserData = UserDataType;
 *       constexpr auto InvalidEventHandler = &InvalidEventHandler;
 *    }
 * 3. Create types for each state
 *     struct State1 {};
 *     struct State2 {};
 * 4. Create Events for transitions
 *     struct Event1 {};
 *     struct Event2 {};
 * 5. Add a member to State data which is variant type of all the states.
 *    struct StateData {
 *      boost::variant<State1, State2> state;
 *    }
 * 6. Declare the handlers
 *     QUIC_DECLARE_STATE_HANDLER(Machine, State1, Event1, State2);
 *     QUIC_DECLARE_STATE_HANDLER(Machine, State1, Event2);
 *
 *     For example, these handlers mean that the state machine Machine can
 *     transition from State1 -> State2 on Event1. When the machine gets Event2
 *     it cannot make any transitions.
 * 7. Implement the handlers
 *     Handler<Machine, State1, Event1>::handle(StateData& data, Event1 event) {
 *       ... do something ...
 *       transit<State2>(data);
 *     }
 *
 * To drive the state machine, whenever a new Event is received:
 *
 *     invokeHandler<Machine, Event1>(data, event1);
 *
 * This will invoke the appropriate handler.
 */

template <class S1, class S2>
struct StateSame : std::false_type {};
template <class S>
struct StateSame<S, S> : std::true_type {};

template <class... Conditions>
struct Or : std::false_type {};

template <class Condition, class... Conditions>
struct Or<Condition, Conditions...>
    : std::conditional<Condition::value, std::true_type, Or<Conditions...>>::
          type {};

template <typename T>
struct Matcher {
  bool operator()(const T&) const {
    return true;
  }
};

template <typename StateType, typename... States>
bool matchesStates(const StateType& state) {
  return folly::variant_match(
      state, Matcher<States>{}..., [](const auto&) { return false; });
}

template <class Machine, class State, class Event, class... AllowedStates>
struct HandlerBase {
  template <class NewState>
  static void transit(typename Machine::StateData& data) {
    static_assert(
        Or<StateSame<NewState, AllowedStates>...>::value, "Invalid transition");
    data.state = NewState();
  }
};

#define QUIC_DECLARE_STATE_HANDLER(machine, state, event, ...)     \
  template <>                                                      \
  class Handler<machine, state, event>                             \
      : public HandlerBase<machine, state, event, ##__VA_ARGS__> { \
   public:                                                         \
    static void handle(                                            \
        typename machine::StateData& data,                         \
        event evt,                                                 \
        typename machine::UserData& userData);                     \
  };

#define QUIC_DECLARE_STATE_HANDLER_T(state, event, ...)                    \
  template <typename Machine>                                              \
  class Handler<Machine, state, event>                                     \
      : public HandlerBase<Machine, state, event, ##__VA_ARGS__> {         \
   public:                                                                 \
    static void handle(                                                    \
        typename Machine::StateData& data,                                 \
        event evt,                                                         \
        typename Machine::UserData&);                                      \
    template <class NewState>                                              \
    static void transit(typename Machine::StateData& data) {               \
      HandlerBase<Machine, state, event, ##__VA_ARGS__>::template transit< \
          NewState>(data);                                                 \
    }                                                                      \
  };

/**
 * Machine needs to have a StateData type which has a member for the state.
 * don't throw exceptions in the handler
 */
template <class Machine, class State, class Event>
struct Handler : public HandlerBase<Machine, State, Event> {
  static void handle(
      typename Machine::StateData& /*state*/,
      Event /*event*/,
      typename Machine::UserData& userData) {
    Machine::InvalidEventHandler(userData);
  }
};

template <class Machine, class Event>
struct state_visitor : public boost::static_visitor<> {
  explicit state_visitor(
      Event event,
      typename Machine::StateData& data,
      typename Machine::UserData& userData)
      : event_(std::move(event)), data_(data), userData_(userData) {}

  template <class State>
  void operator()(const State& /*state*/) {
    Handler<Machine, State, Event>::handle(data_, std::move(event_), userData_);
  }

  Event event_;
  typename Machine::StateData& data_;
  typename Machine::UserData& userData_;
};

template <class Machine, class Event>
void invokeHandler(
    typename Machine::StateData& data,
    Event event,
    typename Machine::UserData& userData) {
  auto visitor =
      state_visitor<Machine, Event>(std::move(event), data, userData);
  return boost::apply_visitor(visitor, data.state);
}
}
