/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#if defined(__linux__)

#include <net/if.h>
#include <quic/xsk/xsk_lib.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#ifndef XDP_USE_NEED_WAKEUP
#define XDP_USE_NEED_WAKEUP (1 << 3)
#endif

int create_xsk() {
  int fd = socket(AF_XDP, SOCK_RAW | SOCK_CLOEXEC, 0);
  if (fd < 0) {
    return -1;
  }
  return fd;
}

int close_xsk(int fd) {
  return close(fd);
}

void* create_umem(int xsk_fd, __u32 num_frames, __u32 frame_size) {
  void* umem_area = mmap(
      NULL,
      num_frames * frame_size,
      PROT_READ | PROT_WRITE,
      MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
      -1,
      0);

  struct xdp_umem_reg mr;
  memset(&mr, 0, sizeof(mr));
  mr.addr = (uintptr_t)umem_area;
  mr.len = num_frames * frame_size;
  mr.chunk_size = frame_size;

  int err = setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr));
  if (err) {
    return nullptr;
  }

  return umem_area;
}

int free_umem(void* umem, __u32 num_frames, __u32 frame_size) {
  return munmap(umem, num_frames * frame_size);
}

int set_completion_ring(int xsk_fd, __u32 num_frames) {
  int err = setsockopt(
      xsk_fd,
      SOL_XDP,
      XDP_UMEM_COMPLETION_RING,
      &num_frames,
      sizeof(num_frames));
  return err;
}

int set_fill_ring(int xsk_fd) {
  // We're not using the fill ring, so I'm just setting the size to 1
  __u32 fill_ring_size = 1;
  int err = setsockopt(
      xsk_fd,
      SOL_XDP,
      XDP_UMEM_FILL_RING,
      &fill_ring_size,
      sizeof(fill_ring_size));
  return err;
}

int set_tx_ring(int xsk_fd, __u32 num_frames) {
  int err =
      setsockopt(xsk_fd, SOL_XDP, XDP_TX_RING, &num_frames, sizeof(num_frames));
  return err;
}

int xsk_get_mmap_offsets(int xsk_fd, struct xdp_mmap_offsets* off) {
  socklen_t optlen;
  int err;

  optlen = sizeof(*off);
  err = getsockopt(xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, off, &optlen);
  if (err)
    return err;

  if (optlen == sizeof(*off))
    return 0;

  return -1;
}

void* map_completion_ring(
    int xsk_fd,
    struct xdp_mmap_offsets* off,
    __u32 num_frames) {
  void* map = mmap(
      NULL,
      off->cr.desc + num_frames * sizeof(__u64),
      PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_POPULATE,
      xsk_fd,
      XDP_UMEM_PGOFF_COMPLETION_RING);
  if (map == MAP_FAILED) {
    return nullptr;
  }

  return map;
}

int unmap_completion_ring(
    void* completion_ring,
    struct xdp_mmap_offsets* off,
    __u32 num_frames) {
  return munmap(completion_ring, off->cr.desc + num_frames * sizeof(__u64));
}

void* map_tx_ring(int xsk_fd, struct xdp_mmap_offsets* off, __u32 num_frames) {
  void* map = mmap(
      NULL,
      off->tx.desc + num_frames * sizeof(struct xdp_desc),
      PROT_READ | PROT_WRITE,
      MAP_SHARED | MAP_POPULATE,
      xsk_fd,
      XDP_PGOFF_TX_RING);
  if (map == MAP_FAILED) {
    return nullptr;
  }

  return map;
}

int unmap_tx_ring(
    void* tx_ring,
    struct xdp_mmap_offsets* off,
    __u32 num_frames) {
  return munmap(tx_ring, off->tx.desc + num_frames * sizeof(struct xdp_desc));
}

int bind_xsk(
    int xsk_fd,
    int queue_id,
    bool zeroCopyEnabled,
    bool useNeedWakeup) {
  struct sockaddr_xdp sxdp = {};
  sxdp.sxdp_family = AF_XDP;
  sxdp.sxdp_ifindex = if_nametoindex("eth0");
  sxdp.sxdp_queue_id = queue_id;

  if (zeroCopyEnabled) {
    sxdp.sxdp_flags |= XDP_ZEROCOPY;
  }

  if (useNeedWakeup) {
    sxdp.sxdp_flags |= XDP_USE_NEED_WAKEUP;
  }

  int err = bind(xsk_fd, (struct sockaddr*)&sxdp, sizeof(sxdp));
  if (err) {
    return -1;
  }
  return 0;
}

int bind_xsk_shared_umem(int xsk_fd, int queue_id, int sharedXskFd) {
  struct sockaddr_xdp sxdp = {};
  sxdp.sxdp_family = AF_XDP;
  sxdp.sxdp_ifindex = if_nametoindex("eth0");
  sxdp.sxdp_queue_id = queue_id;
  sxdp.sxdp_flags = XDP_SHARED_UMEM;
  sxdp.sxdp_shared_umem_fd = sharedXskFd;

  int err = bind(xsk_fd, (struct sockaddr*)&sxdp, sizeof(sxdp));
  if (err) {
    return -1;
  }
  return 0;
}

#endif
