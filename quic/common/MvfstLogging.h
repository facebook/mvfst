/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <glog/logging.h>

// Desktop/server version - pass through to glog without stripping.
// Mobile builds use MvfstLogging-mobile.h instead (via BUCK select()).

#define MVLOG_INFO LOG(INFO)
#define MVLOG_WARNING LOG(WARNING)
#define MVLOG_ERROR LOG(ERROR)
#define MVLOG_FATAL LOG(FATAL)
#define MVLOG_DFATAL LOG(DFATAL)

#define MVVLOG(n) VLOG(n)
#define MVVLOG_IF(n, condition) VLOG_IF(n, condition)

// Pass-through for CHECK macros
#define MVCHECK(condition) CHECK(condition)
#define MVDCHECK(condition) DCHECK(condition)
