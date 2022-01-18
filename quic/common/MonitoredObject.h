/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <functional>
#include <utility>

namespace quic {

/**
 * A wrapper for monitoring an arbitrary object.
 * Whenever the object is accessed, the accessFn is triggered and the wrapped
 * object is passed to it.
 */
template <typename T>
class MonitoredObject {
 public:
  using MonitoredObjectAccessFn = std::function<void(const T&)>;

  MonitoredObject(T object, MonitoredObjectAccessFn accessFn)
      : object_{std::move(object)}, accessFn_{std::move(accessFn)} {}

  MonitoredObject(MonitoredObjectAccessFn accessFn)
      : object_{}, accessFn_{std::move(accessFn)} {}

  class Accessor {
   public:
    Accessor(MonitoredObject<T>* mObject) : mObject_{mObject} {}

    ~Accessor() {
      mObject_->accessFn_(mObject_->object_);
    }

    T* operator->() {
      return &mObject_->object_;
    }

    T& operator*() {
      return mObject_->object_;
    }

    Accessor(const Accessor&) = delete;
    Accessor(Accessor&&) = delete;
    Accessor& operator=(const Accessor&) = delete;
    Accessor& operator=(Accessor&& rhs) = delete;

   private:
    MonitoredObject<T>* mObject_;
  };

  Accessor operator->() {
    return Accessor(this);
  }

  MonitoredObject(const MonitoredObject&) = delete;
  MonitoredObject(MonitoredObject&&) = delete;
  MonitoredObject& operator=(const MonitoredObject&) = delete;
  MonitoredObject& operator=(MonitoredObject&& rhs) = delete;

 private:
  T object_;
  MonitoredObjectAccessFn accessFn_;
};

} // namespace quic
