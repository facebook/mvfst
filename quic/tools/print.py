# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

from __future__ import absolute_import, division, print_function, unicode_literals
import mvfst.base as base
import struct

def conn_id_to_hex(conn_id):
    return struct.pack('<Q', conn_id).hex()

class PrintListener:
    def sent_event(self, event):
        print("sent time=%s, connid=%s, packet_num=%s, size=%s, is_handshake=%s, pure_ack=%s" %
                (str(event.time),
                   conn_id_to_hex(event.conn_id),
                   str(event.packet_num), str(event.encoded_size),
                   str(event.is_handshake), str(event.pure_ack)))

    def acked_event(self, event):
        print("acked time=%s, connid=%s, packet_num=%s" % (str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.packet_num)))

    def lost_event(self, event):
        print("lost time=%s, connid=%s, largest_lost=%s, lost_bytes=%s, lost_packets=%s" %
            (str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.largest_lost_packet_num), str(event.lost_bytes),
            str(event.lost_packets)))

    def recvd_event(self, event):
        print("recvd time=%s, connid=%s, packet_num=%s, size=%s" %
                (str(event.time),
                conn_id_to_hex(event.conn_id),
                str(event.packet_num),
                str(event.size)))

    def handshake_alarm_event(self, event):
        print("handshake alarm time=%s, connid=%s, largest_sent=%s, "\
        "handshake_count=%s, outstanding_handshake_packets=%s, "\
        "outstanding_packets=%s" % (str(event.time), conn_id_to_hex(event.conn_id),
            str(event.largest_sent), str(event.handshake_count),
            str(event.outstanding_handshake_packets),
            str(event.outstanding_packets)))

    def tlp_alarm_event(self, event):
        print("tlp alarm time=%s, connid=%s, largest_sent=%s, "\
        "tlp_count=%s outstanding_packets=%s" %
        (str(event.time), conn_id_to_hex(event.conn_id),
            str(event.largest_sent), str(event.tlp_count),
            str(event.outstanding_packets)))

    def rto_alarm_event(self, event):
        print("rto alarm time=%s, connid=%s, largest_sent=%s, "\
        "largest_sent_before_rto=%s rto_count=%s outstanding_packets=%s" %
        (str(event.time), conn_id_to_hex(event.conn_id),
            str(event.largest_sent), str(event.largest_sent_before_rto),
            str(event.rto_count),
            str(event.outstanding_packets)))

    def rto_verified_event(self, event):
        print("rto verified time=%s, connid=%s, largest_acked_packet=%s, "\
        "largest_sent_before_rto=%s, outstanding_packets=%s" %
        (str(event.time), conn_id_to_hex(event.conn_id),
            str(event.largest_acked_packet),
            str(event.largest_sent_before_rto),
            str(event.outstanding_packets)))

    def packet_clone_event(self, event):
        print("cloned time=%s, connid=%s, packet_num=%s cloned_packet_num=%s " \
              "frames=%s" % (str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.packet_num),
            str(event.cloned_packet_num),
            str(event.frames)))

    def packet_drop_event(self, event):
        print("dropped time=%s, connid=%s, reason=%s" % (
            str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.reason)))

    def udp_recvd_event(self, event):
        print("udp recv time=%s, connid=%s, len=%s" % (
            str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.len)))

    def close_event(self, event):
        print("close time=%s, connid=%s, drain=%s, send_close_immediate=%s, sent=%s, peer=%s" % (
            str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.drain),
            str(event.send_close_immediate),
            str(event.close_sent),
            str(event.peer_sent)))

    def recvd_close_event(self, event):
        print("peer close time=%s, connid=%s, peer=%s" % (
            str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.recvd_close)))

    def cubic_ack_event(self, event):
        print("cubic ack time=%s, connid=%s, state=%s, cwnd=%s, inflight=%s, last_max_cwnd=%s" % (
            str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.state),
            str(event.cwnd),
            str(event.inflight),
            str(event.last_max_cwnd)))

    def cubic_steady_cwnd_event(self, event):
        print("cubic steady cwnd time=%s, connid=%s, cur_cwnd=%s, delta=%s, time_to_origin=%sms, time_elapsed=%sms" % (
            str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.curr_cwnd),
            str(event.delta),
            str(event.time_to_origin),
            str(event.time_elapsed)))

    def fst_trace_event(self, event):
        print("trace time=%s, connid=%s, log=%s" % (
            str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.log)))

    def stream_event(self, event):
        print("stream evt=%s time=%s, connid=%s, stream_id=%s, duration=%s" % (
            str(event.name),
            str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.stream_id),
            str(event.time_since_start)))

    def pacing_update(self, event):
        print("pacing update=%s, connid=%s, interval=%s, burst=%s" % (
            str(event.time),
            conn_id_to_hex(event.conn_id),
            str(event.interval),
            str(event.burst)))


if __name__ == "__main__":
    base.start_listening(PrintListener())
