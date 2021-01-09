/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

#include <quic/common/Variant.h>

#include <gtest/gtest.h>

bool& destructor_called() {
  static bool destructor_called = false;
  return destructor_called;
}

struct A {
  A() = default;

  ~A() {
    destructor_called() = true;
  }

  A(A&&) {
    moved = true;
  }

  A(const A&) {
    copied = true;
  }

  A& operator=(A&&) {
    moveAssign = true;
    return *this;
  }

  A& operator=(const A&) {
    copyAssign = true;
    return *this;
  }

  bool operator==(const A&) const {
    return true;
  }

  bool moved{false};
  bool copied{false};
  bool moveAssign{false};
  bool copyAssign{false};
};

struct B {
  B() = default;

  B(B&&) {
    moved = true;
  }

  B(const B&) {
    copied = true;
  }

  bool operator==(const B&) const {
    return true;
  }

  bool moved{false};
  bool copied{false};
};

struct C {
  bool operator==(const C&) const {
    return true;
  }
};

#define TEST_VARIANT(F, ...) \
  F(A, __VA_ARGS__)          \
  F(B, __VA_ARGS__)          \
  F(C, __VA_ARGS__)

DECLARE_VARIANT_TYPE(TestVariant, TEST_VARIANT)

TEST(Variant, TestCreateVariant) {
  TestVariant variantA{A()};
  TestVariant variantB{B()};
  TestVariant variantC{C()};

  EXPECT_EQ(variantA.type(), TestVariant::Type::A);
  EXPECT_EQ(variantB.type(), TestVariant::Type::B);
  EXPECT_EQ(variantC.type(), TestVariant::Type::C);

  EXPECT_NE(variantA.asA(), nullptr);
  EXPECT_NE(variantB.asB(), nullptr);
  EXPECT_NE(variantC.asC(), nullptr);

  EXPECT_EQ(variantA.asB(), nullptr);
  EXPECT_EQ(variantA.asC(), nullptr);

  EXPECT_EQ(variantB.asA(), nullptr);
  EXPECT_EQ(variantB.asC(), nullptr);

  EXPECT_EQ(variantC.asA(), nullptr);
  EXPECT_EQ(variantC.asB(), nullptr);
}

TEST(Variant, TestMoveVariant) {
  TestVariant variantA{A()};
  TestVariant variantA1{std::move(variantA)};
  EXPECT_TRUE(variantA1.asA()->moved);

  destructor_called() = false;
  variantA = std::move(variantA1);
  EXPECT_TRUE(destructor_called());
  EXPECT_TRUE(variantA.asA()->moved);
  EXPECT_FALSE(variantA.asA()->moveAssign);
}

TEST(Variant, TestMoveVariantDifferentType) {
  TestVariant variantA{A()};
  TestVariant variantB{B()};
  destructor_called() = false;
  variantA = std::move(variantB);
  EXPECT_TRUE(destructor_called());
  ASSERT_NE(variantA.asB(), nullptr);
  EXPECT_TRUE(variantA.asB()->moved);
}

TEST(Variant, TestCopyVariant) {
  TestVariant variantA{A()};
  TestVariant variantA1{variantA};
  EXPECT_TRUE(variantA1.asA()->copied);

  destructor_called() = false;
  variantA = variantA1;
  EXPECT_TRUE(destructor_called());
  EXPECT_TRUE(variantA.asA()->copied);
  EXPECT_FALSE(variantA.asA()->copyAssign);
}

TEST(Variant, TestCopyVariantDifferentType) {
  TestVariant variantA{A()};
  TestVariant variantB{B()};
  destructor_called() = false;
  variantA = variantB;
  EXPECT_TRUE(destructor_called());
  ASSERT_NE(variantA.asB(), nullptr);
  EXPECT_TRUE(variantA.asB()->copied);
}
