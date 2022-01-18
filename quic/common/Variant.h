/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

namespace quic {

#define UNION_TYPE(X, ...) X X##_;

#define ENUM_TYPES(X, ...) X,

#define UNION_ACCESSOR(X, ...) \
  X* as##X() {                 \
    if (type_ == Type::X) {    \
      return &X##_;            \
    }                          \
    return nullptr;            \
  }

#define CONST_UNION_ACCESSOR(X, ...) \
  const X* as##X() const {           \
    if (type_ == Type::X) {          \
      return &X##_;                  \
    }                                \
    return nullptr;                  \
  }

#define UNION_ACCESSOR_TYPE_TPL(X, ...) \
  X* get(Identity<X>) {                 \
    if (type_ == Type::X) {             \
      return &X##_;                     \
    }                                   \
    return nullptr;                     \
  }

#define CONST_UNION_ACCESSOR_TYPE_TPL(X, ...) \
  const X* get(Identity<X>) const {           \
    if (type_ == Type::X) {                   \
      return &X##_;                           \
    }                                         \
    return nullptr;                           \
  }

#define UNION_CTORS(X, NAME)     \
  NAME(X&& x) : type_(Type::X) { \
    new (&X##_) X(std::move(x)); \
  }

#define UNION_COPY_CTORS(X, NAME)     \
  NAME(const X& x) : type_(Type::X) { \
    new (&X##_) X(x);                 \
  }

#define UNION_MOVE_CASES(X, other)        \
  case Type::X:                           \
    new (&X##_) X(std::move(other.X##_)); \
    break;

#define UNION_COPY_CASES(X, other) \
  case Type::X:                    \
    new (&X##_) X(other.X##_);     \
    break;

#define DESTRUCTOR_CASES(X, ...) \
  case Type::X:                  \
    X##_.~X();                   \
    break;

#define UNION_EQUALITY_CASES(X, other) \
  case Type::X:                        \
    return X##_ == *other.as##X();

#define DECLARE_VARIANT_TYPE(NAME, X)                         \
  struct NAME {                                               \
    enum class Type { X(ENUM_TYPES) };                        \
                                                              \
    X(UNION_CTORS, NAME)                                      \
                                                              \
    X(UNION_COPY_CTORS, NAME)                                 \
                                                              \
    NAME(NAME&& other) {                                      \
      switch (other.type_) { X(UNION_MOVE_CASES, other) }     \
      type_ = other.type_;                                    \
    }                                                         \
                                                              \
    NAME& operator=(NAME&& other) {                           \
      destroyVariant();                                       \
      switch (other.type_) { X(UNION_MOVE_CASES, other) }     \
      type_ = other.type_;                                    \
      return *this;                                           \
    }                                                         \
                                                              \
    NAME(const NAME& other) {                                 \
      switch (other.type_) { X(UNION_COPY_CASES, other) }     \
      type_ = other.type_;                                    \
    }                                                         \
                                                              \
    NAME& operator=(const NAME& other) {                      \
      destroyVariant();                                       \
      switch (other.type_) { X(UNION_COPY_CASES, other) }     \
      type_ = other.type_;                                    \
      return *this;                                           \
    }                                                         \
                                                              \
    bool operator==(const NAME& other) const {                \
      if (other.type() != type_) {                            \
        return false;                                         \
      }                                                       \
      switch (other.type_) { X(UNION_EQUALITY_CASES, other) } \
      return false;                                           \
    }                                                         \
                                                              \
    ~NAME() {                                                 \
      destroyVariant();                                       \
    }                                                         \
                                                              \
    Type type() const {                                       \
      return type_;                                           \
    }                                                         \
                                                              \
    X(UNION_ACCESSOR)                                         \
                                                              \
    X(CONST_UNION_ACCESSOR)                                   \
                                                              \
    template <typename T>                                     \
    T* get() {                                                \
      return get(Identity<T>());                              \
    }                                                         \
                                                              \
    template <typename T>                                     \
    const T* get() const {                                    \
      return get(Identity<T>());                              \
    }                                                         \
                                                              \
   private:                                                   \
    template <typename T>                                     \
    struct Identity {                                         \
      typedef T type;                                         \
    };                                                        \
                                                              \
    union {                                                   \
      X(UNION_TYPE)                                           \
    };                                                        \
                                                              \
    X(UNION_ACCESSOR_TYPE_TPL)                                \
                                                              \
    X(CONST_UNION_ACCESSOR_TYPE_TPL)                          \
                                                              \
    void destroyVariant() {                                   \
      switch (type_) { X(DESTRUCTOR_CASES) }                  \
    }                                                         \
                                                              \
    Type type_;                                               \
  };

} // namespace quic
