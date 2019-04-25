#!/usr/bin/env bcc-py
# @lint-avoid-python-3-compatibility-imports

# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import absolute_import
from __future__ import division
from __future__ import unicode_literals
from __future__ import print_function
import argparse
from bcc import BPF, USDT
import ctypes as ct
import string
import random

program = """
struct packet_sent_event {
    u64 evt_time;
    u64 conn_id;
    u64 packet_num;
    u64 encoded_size;
    int is_handshake;
    int pure_ack;
};

BPF_PERF_OUTPUT(PREFIX_packets_sent);

int on_packet_sent(struct pt_regs *ctx) {
    struct packet_sent_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.packet_num);
    bpf_usdt_readarg(3, ctx, &evt.encoded_size);
    bpf_usdt_readarg(4, ctx, &evt.is_handshake);
    bpf_usdt_readarg(5, ctx, &evt.pure_ack);
    PREFIX_packets_sent.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct packet_acked_event {
    u64 evt_time;
    u64 conn_id;
    u64 packet_num;
};

BPF_PERF_OUTPUT(PREFIX_packets_acked);

int on_packet_acked(struct pt_regs *ctx) {
    struct packet_acked_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.packet_num);
    PREFIX_packets_acked.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct packet_lost_event {
    u64 evt_time;
    u64 conn_id;
    u64 largest_lost_packet_num;
    u64 lost_bytes;
    u32 lost_packets;
};

BPF_PERF_OUTPUT(PREFIX_packets_lost);

int on_packets_lost(struct pt_regs *ctx) {
    struct packet_lost_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.largest_lost_packet_num);
    bpf_usdt_readarg(3, ctx, &evt.lost_bytes);
    bpf_usdt_readarg(4, ctx, &evt.lost_packets);
    PREFIX_packets_lost.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct packet_recvd_event {
    u64 evt_time;
    u64 conn_id;
    u64 packet_num;
    u64 size;
};

BPF_PERF_OUTPUT(PREFIX_packets_recvd);

int on_packet_recvd(struct pt_regs *ctx) {
    struct packet_recvd_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.packet_num);
    bpf_usdt_readarg(3, ctx, &evt.size);
    PREFIX_packets_recvd.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct handshake_alarm_event {
    u64 evt_time;
    u64 conn_id;
    u64 largest_sent;
    u64 handshake_count;
    u64 outstanding_handshake_packets;
    u64 outstanding_packets;
};

BPF_PERF_OUTPUT(PREFIX_handshake_events);

int on_handshake_alarm(struct pt_regs *ctx) {
    struct handshake_alarm_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.largest_sent);
    bpf_usdt_readarg(3, ctx, &evt.handshake_count);
    bpf_usdt_readarg(4, ctx, &evt.outstanding_handshake_packets);
    bpf_usdt_readarg(5, ctx, &evt.outstanding_packets);
    PREFIX_handshake_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct rto_alarm_event {
    u64 evt_time;
    u64 conn_id;
    u64 largest_sent;
    u64 largest_sent_before_rto;
    u64 rto_count;
    u64 outstanding_packets;
};

BPF_PERF_OUTPUT(PREFIX_rto_events);

int on_rto_alarm(struct pt_regs *ctx) {
    struct rto_alarm_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.largest_sent);
    bpf_usdt_readarg(3, ctx, &evt.largest_sent_before_rto);
    bpf_usdt_readarg(4, ctx, &evt.rto_count);
    bpf_usdt_readarg(5, ctx, &evt.outstanding_packets);
    PREFIX_rto_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct tlp_alarm_event {
    u64 evt_time;
    u64 conn_id;
    u64 largest_sent;
    u64 tlp_count;
    u64 outstanding_packets;
};

BPF_PERF_OUTPUT(PREFIX_tlp_events);

int on_tlp_alarm(struct pt_regs *ctx) {
    struct tlp_alarm_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.largest_sent);
    bpf_usdt_readarg(3, ctx, &evt.tlp_count);
    bpf_usdt_readarg(4, ctx, &evt.outstanding_packets);
    PREFIX_tlp_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct rto_verified_event {
    u64 evt_time;
    u64 conn_id;
    u64 largest_acked_packet;
    u64 largest_sent_before_rto;
    u64 outstanding_packets;
};

BPF_PERF_OUTPUT(PREFIX_rto_verified_events);

int on_rto_verified(struct pt_regs *ctx) {
    struct rto_verified_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.largest_acked_packet);
    bpf_usdt_readarg(3, ctx, &evt.largest_sent_before_rto);
    bpf_usdt_readarg(4, ctx, &evt.outstanding_packets);
    PREFIX_rto_verified_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

/*
struct packet_clone_event {
    u64 evt_time;
    u64 conn_id;
    u64 packet_num;
    u64 cloned_packet_num;
    u64 frames;
};

BPF_PERF_OUTPUT(PREFIX_packets_cloned);

int on_packet_clone(struct pt_regs *ctx) {
    struct packet_clone_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.packet_num);
    bpf_usdt_readarg(3, ctx, &evt.cloned_packet_num);
    bpf_usdt_readarg(4, ctx, &evt.frames);
    PREFIX_packets_cloned.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
*/

struct packet_drop_event {
    u64 evt_time;
    u64 conn_id;
    char reason[50];
};

BPF_PERF_OUTPUT(PREFIX_packet_drop_events);

int on_packet_drop(struct pt_regs *ctx) {
    struct packet_drop_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg_p(2, ctx, &evt.reason, sizeof(evt.reason) - 1);
    PREFIX_packet_drop_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct udp_recvd_event {
    u64 evt_time;
    u64 conn_id;
    u64 len;
};

BPF_PERF_OUTPUT(PREFIX_udp_recvd_events);

int on_udp_recvd(struct pt_regs *ctx) {
    struct udp_recvd_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.len);
    PREFIX_udp_recvd_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct close_event {
    u64 evt_time;
    u64 conn_id;
    u64 drain;
    u64 send_close_immediate;
    char close_sent[100];
    char peer_sent[100];
};

BPF_PERF_OUTPUT(PREFIX_close_events);

int on_close(struct pt_regs *ctx) {
    struct close_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.drain);
    bpf_usdt_readarg(3, ctx, &evt.send_close_immediate);
    bpf_usdt_readarg_p(4, ctx, &evt.close_sent, sizeof(evt.close_sent) - 1);
    bpf_usdt_readarg_p(5, ctx, &evt.peer_sent, sizeof(evt.peer_sent) - 1);
    PREFIX_close_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

BPF_PERF_OUTPUT(PREFIX_recvd_close_event);

struct recvd_close_event {
    u64 evt_time;
    u64 conn_id;
    char close_recvd[100];
};

int on_recvd_close(struct pt_regs *ctx) {
    struct recvd_close_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg_p(2, ctx, &evt.close_recvd, sizeof(evt.close_recvd) - 1);
    PREFIX_recvd_close_event.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct cubic_ack_event {
    u64 evt_time;
    u64 conn_id;
    char newstate[10];
    u64 cwnd;
    u64 inflight_bytes;
    u64 last_max_cwnd;
};

BPF_PERF_OUTPUT(PREFIX_cubic_ack_event);

int on_cubic_ack(struct pt_regs* ctx) {
    struct cubic_ack_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg_p(2, ctx, &evt.newstate, sizeof(evt.newstate) - 1);
    bpf_usdt_readarg(3, ctx, &evt.cwnd);
    bpf_usdt_readarg(4, ctx, &evt.inflight_bytes);
    bpf_usdt_readarg(5, ctx, &evt.last_max_cwnd);
    PREFIX_cubic_ack_event.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

struct cubic_steady_cwnd_event {
    u64 evt_time;
    u64 conn_id;
    u64 curr_cwnd;
    long long delta;
    u64 time_to_origin_ms;
    u64 time_elapsed_ms;
};

BPF_PERF_OUTPUT(PREFIX_cubic_steady_cwnd_event);

int on_cubic_steady_cwnd_changed(struct pt_regs* ctx) {
    struct cubic_steady_cwnd_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg(2, ctx, &evt.curr_cwnd);
    bpf_usdt_readarg(3, ctx, &evt.delta);
    bpf_usdt_readarg(4, ctx, &evt.time_to_origin_ms);
    bpf_usdt_readarg(5, ctx, &evt.time_elapsed_ms);
    PREFIX_cubic_steady_cwnd_event.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

BPF_PERF_OUTPUT(PREFIX_fst_trace_events);

struct fst_trace_event {
    u64 evt_time;
    u64 conn_id;
    char log[100];
};

int on_fst_trace_event(struct pt_regs* ctx) {
    struct fst_trace_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg_p(2, ctx, &evt.log, sizeof(evt.log) - 1);
    PREFIX_fst_trace_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

BPF_PERF_OUTPUT(PREFIX_stream_events);

struct stream_event {
    u64 evt_time;
    u64 conn_id;
    char name[20];
    u64 stream_id;
    u64 time_since_start;
};

int on_stream_event(struct pt_regs* ctx) {
    struct stream_event evt = {};
    evt.evt_time = bpf_ktime_get_ns();
    bpf_usdt_readarg(1, ctx, &evt.conn_id);
    bpf_usdt_readarg_p(2, ctx, &evt.name, sizeof(evt.name) - 1);
    bpf_usdt_readarg(3, ctx, &evt.stream_id);
    bpf_usdt_readarg(4, ctx, &evt.time_since_start);
    PREFIX_stream_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

BPF_PERF_OUTPUT(PREFIX_pacing_updates);

struct pacing_update_event {
    u64 evt_time;
    u64 conn_id;
    u64 interval;
    u64 burst;
};

int on_pacing_update(struct pt_regs* ctx) {
   struct pacing_update_event evt = {};
   evt.evt_time = bpf_ktime_get_ns();
   bpf_usdt_readarg(1, ctx, &evt.conn_id);
   bpf_usdt_readarg(2, ctx, &evt.interval);
   bpf_usdt_readarg(3, ctx, &evt.burst);
   PREFIX_pacing_updates.perf_submit(ctx, &evt, sizeof(evt));
   return 0;
}

"""

def randomword(length):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

randprefix = randomword(4)

parser = argparse.ArgumentParser(
    description="Trace quic events",
    formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("pid", type=int, help="pid to attach to")
args = parser.parse_args()

usdt = USDT(pid=args.pid)
usdt.enable_probe_or_bail("packet_acked", "on_packet_acked")
usdt.enable_probe_or_bail("packet_sent", "on_packet_sent")
usdt.enable_probe("packets_lost", "on_packets_lost")
usdt.enable_probe("packet_recvd", "on_packet_recvd")
usdt.enable_probe("rto_alarm", "on_rto_alarm")
usdt.enable_probe("tlp_alarm", "on_tlp_alarm")
usdt.enable_probe("handshake_alarm", "on_handshake_alarm")
usdt.enable_probe("rto_verified", "on_rto_verified")
#usdt.enable_probe("packet_clone", "on_packet_clone")
usdt.enable_probe("packet_drop", "on_packet_drop")
usdt.enable_probe("conn_close", "on_close")
usdt.enable_probe("recvd_close", "on_recvd_close")
usdt.enable_probe("cubic_ack", "on_cubic_ack")
usdt.enable_probe("cubic_steady_cwnd", "on_cubic_steady_cwnd_changed")
usdt.enable_probe("pacing_update", "on_pacing_update")
try:
    usdt.enable_probe("udp_recvd", "on_udp_recvd")
    usdt.enable_probe("fst_trace", "on_fst_trace_event")
    usdt.enable_probe("stream_event", "on_stream_event")
except:
    pass

CFLAGS = [
]

replaced = bytes(program.replace('PREFIX', randprefix), 'utf-8')
bpf = BPF(text=replaced, usdt_contexts=[usdt], cflags=CFLAGS)
print("Tracing quic events in process %d ... Ctrl-C to quit." %
        (args.pid))

# not necessarily thread safe, but we just need a best effort
# kind of thing
running = True


def sent_event(listener):
    class PacketSentEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("packet_num", ct.c_ulonglong),
            ("encoded_size", ct.c_ulonglong),
            ("is_handshake", ct.c_int),
            ("pure_ack", ct.c_int),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(PacketSentEvent)).contents
        listener.sent_event(event)
    return inner_call


def acked_event(listener):
    class PacketAckedEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("packet_num", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(PacketAckedEvent)).contents
        listener.acked_event(event)
    return inner_call


def lost_event(listener):
    class PacketLostEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("largest_lost_packet_num", ct.c_ulonglong),
            ("lost_bytes", ct.c_ulonglong),
            ("lost_packets", ct.c_ulong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(PacketLostEvent)).contents
        listener.lost_event(event)
    return inner_call


def recvd_event(listener):
    class PacketRecvdEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("packet_num", ct.c_ulonglong),
            ("size", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(PacketRecvdEvent)).contents
        listener.recvd_event(event)
    return inner_call


def handshake_event(listener):
    class HandshakeAlarmEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("largest_sent", ct.c_ulonglong),
            ("handshake_count", ct.c_ulonglong),
            ("outstanding_handshake_packets", ct.c_ulonglong),
            ("outstanding_packets", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(HandshakeAlarmEvent)).contents
        listener.handshake_alarm_event(event)
    return inner_call


def tlp_event(listener):
    class TLPAlarmEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("largest_sent", ct.c_ulonglong),
            ("tlp_count", ct.c_ulonglong),
            ("outstanding_packets", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(TLPAlarmEvent)).contents
        listener.tlp_alarm_event(event)
    return inner_call


def rto_event(listener):
    class RTOAlarmEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("largest_sent", ct.c_ulonglong),
            ("largest_sent_before_rto", ct.c_ulonglong),
            ("rto_count", ct.c_ulonglong),
            ("outstanding_packets", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(RTOAlarmEvent)).contents
        listener.rto_alarm_event(event)
    return inner_call


def rto_verified_event(listener):
    class RTOVerifiedEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("largest_acked_packet", ct.c_ulonglong),
            ("largest_sent_before_rto", ct.c_ulonglong),
            ("outstanding_packets", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(RTOVerifiedEvent)).contents
        listener.rto_verified_event(event)
    return inner_call


def packet_clone_event(listener):
    class PacketCloneEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("packet_num", ct.c_ulonglong),
            ("cloned_packet_num", ct.c_ulonglong),
            ("frames", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(PacketCloneEvent)).contents
        listener.packet_clone_event(event)
    return inner_call


def packet_drop_event(listener):
    class PacketDropEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("_reason", ct.c_char * 50),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(PacketDropEvent)).contents
        event.reason = event._reason.decode('utf-8')
        listener.packet_drop_event(event)
    return inner_call


def udp_recvd_event(listener):
    class UdpRecvdEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("len", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(UdpRecvdEvent)).contents
        listener.udp_recvd_event(event)
    return inner_call


def close_event(listener):
    class CloseEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("drain", ct.c_ulonglong),
            ("send_close_immediate", ct.c_ulonglong),
            ("_close_sent", ct.c_char * 100),
            ("_peer_sent", ct.c_char * 100),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(CloseEvent)).contents
        event.close_sent = event._close_sent.decode('utf-8')
        event.peer_sent = event._peer_sent.decode('utf-8')
        listener.close_event(event)
    return inner_call

def recvd_close_event(listener):
    class RecvdCloseEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("_recvd_close", ct.c_char * 100),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(RecvdCloseEvent)).contents
        event.recvd_close = event._recvd_close.decode('utf-8')
        listener.recvd_close_event(event)
    return inner_call


def cubic_ack_event(listener):
    class CubicAckEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("_state", ct.c_char * 10),
            ("cwnd", ct.c_ulonglong),
            ("inflight", ct.c_ulonglong),
            ("last_max_cwnd", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(CubicAckEvent)).contents
        event.state = event._state.decode('utf-8')
        listener.cubic_ack_event(event)
    return inner_call


def cubic_steady_cwnd_event(listener):
    class CubicSteadyCwndChangedEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("curr_cwnd", ct.c_ulonglong),
            ("delta", ct.c_longlong),
            ("time_to_origin", ct.c_ulonglong),
            ("time_elapsed", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(CubicSteadyCwndChangedEvent)).contents
        listener.cubic_steady_cwnd_event(event)
    return inner_call


def fst_trace_event(listener):
    class FstTraceEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("_log", ct.c_char * 100),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(FstTraceEvent)).contents
        event.log = event._log.decode('utf-8')
        listener.fst_trace_event(event)
    return inner_call


def stream_event(listener):
    class StreamEvent(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("_name", ct.c_char * 20),
            ("stream_id", ct.c_ulonglong),
            ("time_since_start", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(StreamEvent)).contents
        event.name = event._name.decode('utf-8')
        listener.stream_event(event)
    return inner_call


def pacing_update(listener):
    class PacingUpdate(ct.Structure):
        _fields_ = [
            ("time", ct.c_ulonglong),
            ("conn_id", ct.c_ulonglong),
            ("interval", ct.c_ulonglong),
            ("burst", ct.c_ulonglong),
        ]
    def inner_call(cpu, data, size):
        event = ct.cast(data, ct.POINTER(PacingUpdate)).contents
        listener.pacing_update(event)
    return inner_call


PAGE_COUNT=4096

def start_listening(listener):
    packets_sent = "%s_packets_sent" % randprefix
    packets_acked = "%s_packets_acked" % randprefix
    packets_lost = "%s_packets_lost" % randprefix
    packets_recvd = "%s_packets_recvd" % randprefix
    handshake_events = "%s_handshake_events" % randprefix
    tlp_events = "%s_tlp_events" % randprefix
    rto_events = "%s_rto_events" % randprefix
    rto_verified_events = "%s_rto_verified_events" % randprefix
    #packets_cloned = "%s_packets_cloned" % randprefix
    packets_drop = "%s_packet_drop_events" % randprefix
    udp_recvd = "%s_udp_recvd_events" % randprefix
    conn_close = "%s_close_events" % randprefix
    recvd_close = "%s_recvd_close_event" % randprefix
    cubic_ack = "%s_cubic_ack_event" % randprefix
    cubic_steady_cwnd = "%s_cubic_steady_cwnd_event" % randprefix
    fst_trace = "%s_fst_trace_events" % randprefix
    stream_trace_event = "%s_stream_events" % randprefix
    pacing_update_event = "%s_pacing_updates" % randprefix

    print("randprefix=%s" % randprefix)

    bpf[packets_sent].open_perf_buffer(sent_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[packets_acked].open_perf_buffer(acked_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[packets_lost].open_perf_buffer(lost_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[packets_recvd].open_perf_buffer(recvd_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[handshake_events].open_perf_buffer(handshake_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[tlp_events].open_perf_buffer(tlp_event(listener), page_cnt=PAGE_COUNT)
    bpf[rto_events].open_perf_buffer(rto_event(listener), page_cnt=PAGE_COUNT)
    bpf[rto_verified_events].open_perf_buffer(rto_verified_event(listener),
            page_cnt=PAGE_COUNT)
    #bpf[packets_cloned].open_perf_buffer(packet_clone_event(listener),
    #        page_cnt=PAGE_COUNT)
    bpf[packets_drop].open_perf_buffer(packet_drop_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[udp_recvd].open_perf_buffer(udp_recvd_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[conn_close].open_perf_buffer(close_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[recvd_close].open_perf_buffer(recvd_close_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[cubic_ack].open_perf_buffer(cubic_ack_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[cubic_steady_cwnd].open_perf_buffer(cubic_steady_cwnd_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[fst_trace].open_perf_buffer(fst_trace_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[stream_trace_event].open_perf_buffer(stream_event(listener),
            page_cnt=PAGE_COUNT)
    bpf[pacing_update_event].open_perf_buffer(pacing_update(listener),
            page_cnt=PAGE_COUNT)
    while running:
        bpf.perf_buffer_poll()
