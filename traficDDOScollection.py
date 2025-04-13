@set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
def _flow_stats_reply_handler(self, ev):
    timestamp = datetime.now()
    timestamp = timestamp.timestamp()
    icmp_code = -1
    icmp_type = -1
    tp_src = 0
    tp_dst = 0

    file0 = open("FlowStatsfile.csv", "a+")

    body = ev.msg.body
    for stat in sorted([flow for flow in body if (flow.priority == 1)], key=lambda flow:
    (flow.match['eth_type'], flow.match['ipv4_src'], flow.match['ipv4_dst'], flow.match['ip_proto'])):

        ip_src = stat.match['ipv4_src']
        ip_dst = stat.match['ipv4_dst']
        ip_proto = stat.match['ip_proto']

        if stat.match['ip_proto'] == 1:
            icmp_code = stat.match['icmpv4_code']
            icmp_type = stat.match['icmpv4_type']

        elif stat.match['ip_proto'] == 6:
            tp_src = stat.match['tcp_src']
            tp_dst = stat.match['tcp_dst']

        elif stat.match['ip_proto'] == 17:
            tp_src = stat.match['udp_src']
            tp_dst = stat.match['udp_dst']

        flow_id = str(ip_src) + str(tp_src) + str(ip_dst) + str(tp_dst) + str(ip_proto)

        try:
            packet_count_per_second = stat.packet_count / stat.duration_sec
            packet_count_per_nsecond = stat.packet_count / stat.duration_nsec
        except:
            packet_count_per_second = 0
            packet_count_per_nsecond = 0

        try:
            byte_count_per_second = stat.byte_count / stat.duration_sec
            byte_count_per_nsecond = stat.byte_count / stat.duration_nsec
        except:
            byte_count_per_second = 0
            byte_count_per_nsecond = 0

        file0.write("{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n"
                    .format(timestamp, ev.msg.datapath.id, flow_id, ip_src, tp_src, ip_dst, tp_dst,
                            stat.match['ip_proto'], icmp_code, icmp_type,
                            stat.duration_sec, stat.duration_nsec,
                            stat.idle_timeout, stat.hard_timeout,
                            stat.flags, stat.packet_count, stat.byte_count,
                            packet_count_per_second, packet_count_per_nsecond,
                            byte_count_per_second, byte_count_per_nsecond, 1))
    file0.close()