/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/MvfstCheck.h>

#include <functional>
#include <type_traits>

namespace quic {

/**
 * A lightweight non-owning reference to a callable object.
 *
 * Similar to folly::FunctionRef but with minimal dependencies.
 * Use this for callbacks that are executed immediately and never stored.
 */
template <typename FunctionType>
class FunctionRef;

template <typename ReturnType, typename... Args>
class FunctionRef<ReturnType(Args...)> final {
  using Call = ReturnType (*)(void*, Args...);
  using FnPtr = ReturnType (*)(Args...);

  // For callable objects (lambdas, functors)
  template <typename Fun>
  static ReturnType callObject(void* object, Args... args) {
    auto& ref =
        *static_cast<std::add_pointer_t<std::remove_reference_t<Fun>>>(object);
    return static_cast<ReturnType>(
        std::invoke(ref, static_cast<Args&&>(args)...));
  }

  // For function pointers
  static ReturnType callFnPtr(void* object, Args... args) {
    auto fn = reinterpret_cast<FnPtr>(object);
    return static_cast<ReturnType>(fn(static_cast<Args&&>(args)...));
  }

  void* object_{nullptr};
  Call call_{nullptr};

 public:
  constexpr FunctionRef() = default;

  constexpr explicit FunctionRef(std::nullptr_t) noexcept {}

  // Constructor for function pointers
  /* implicit */ constexpr FunctionRef(FnPtr fn) noexcept
      : object_(reinterpret_cast<void*>(fn)), call_(&FunctionRef::callFnPtr) {}

  // Constructor for callable objects (lambdas, functors)
  template <
      typename Fun,
      std::enable_if_t<
          !std::is_same_v<FunctionRef, std::decay_t<Fun>> &&
              !std::is_same_v<FnPtr, std::decay_t<Fun>> &&
              std::is_invocable_r_v<ReturnType, Fun&, Args...>,
          int> = 0>
  /* implicit */ constexpr FunctionRef(Fun&& fun) noexcept
      : object_(
            const_cast<void*>(static_cast<const void*>(std::addressof(fun)))),
        call_(&FunctionRef::template callObject<Fun>) {}

  ReturnType operator()(Args... args) const {
    MVCHECK(object_ != nullptr);
    return call_(object_, static_cast<Args&&>(args)...);
  }

  constexpr explicit operator bool() const noexcept {
    return object_ != nullptr;
  }
};

} // namespace quic
