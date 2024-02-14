/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#if defined(__linux__)

#include <linux/if_xdp.h>
#include <stdint.h>

// Returns descriptor on succeess, negative value on failure
int create_xsk();

// Returns 0 on success, negative value on failure
int close_xsk(int fd);

// Returns nullptr on failure
void* create_umem(int xsk_fd, __u32 num_frames, __u32 frame_size);

// Returns 0 on success, negative value on failure
int free_umem(void* umem, __u32 num_frames, __u32 frame_size);

// Returns 0 on success, negative value on failure
int set_completion_ring(int xsk_fd, __u32 num_frames);

// Although we're not doing rx from the socket, we still need to
// set the fill ring. See
// https://elixir.bootlin.com/linux/v5.12/source/net/xdp/xsk.c#L776
// Returns 0 on success, negative value on failure.
int set_fill_ring(int xsk_fd);

// Returns 0 on success, negative value on failure
int set_tx_ring(int xsk_fd, __u32 num_frames);

// Returns 0 on success, negative value on failure
int xsk_get_mmap_offsets(int fd, struct xdp_mmap_offsets* off);

// Returns completion ring on success, nullptr on failure
void* map_completion_ring(
    int xsk_fd,
    struct xdp_mmap_offsets* off,
    __u32 num_frames);

// Returns 0 on success, negative value on failure
int unmap_completion_ring(
    void* completion_ring,
    struct xdp_mmap_offsets* off,
    __u32 num_frames);

// Returns tx ring on success, nullptr on failure
void* map_tx_ring(int xsk_fd, struct xdp_mmap_offsets* off, __u32 num_frames);

// Returns 0 on success, negative value on failure
int unmap_tx_ring(
    void* tx_ring,
    struct xdp_mmap_offsets* off,
    __u32 num_frames);

// Returns 0 on success, negative value on failure
int bind_xsk(
    int xsk_fd,
    int queue_id,
    bool zeroCopyEnabled,
    bool useNeedWakeup);

int bind_xsk_shared_umem(int xsk_fd, int queue_id, int sharedXskFd);

#endif
