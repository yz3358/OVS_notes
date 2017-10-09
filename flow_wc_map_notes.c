/* Return a map of possible fields for a packet of the same type as 'flow'.
 * Including extra bits in the returned mask is not wrong, it is just less
 * optimal.
 *
 * This is a less precise version of flow_wildcards_init_for_packet() above. */
void
flow_wc_map(const struct flow *flow, struct flowmap *map)
{
    /* Update this function whenever struct flow changes. */
    BUILD_ASSERT_DECL(FLOW_WC_SEQ == 36);

    flowmap_init(map);

    if (flow_tnl_dst_is_set(&flow->tunnel)) {
        FLOWMAP_SET__(map, tunnel, offsetof(struct flow_tnl, metadata));
        if (!(flow->tunnel.flags & FLOW_TNL_F_UDPIF)) {
            if (flow->tunnel.metadata.present.map) {
                FLOWMAP_SET(map, tunnel.metadata);
            }
        } else {
            FLOWMAP_SET(map, tunnel.metadata.present.len);
            FLOWMAP_SET__(map, tunnel.metadata.opts.gnv,
                          flow->tunnel.metadata.present.len);
        }
    }

    /* Metadata fields that can appear on packet input. */
    FLOWMAP_SET(map, skb_priority);
    FLOWMAP_SET(map, pkt_mark);
    FLOWMAP_SET(map, recirc_id);
    FLOWMAP_SET(map, dp_hash);
    FLOWMAP_SET(map, in_port);
    FLOWMAP_SET(map, dl_dst);
    FLOWMAP_SET(map, dl_src);
    FLOWMAP_SET(map, dl_type);
    FLOWMAP_SET(map, vlan_tci);
    FLOWMAP_SET(map, ct_state);
    FLOWMAP_SET(map, ct_zone);
    FLOWMAP_SET(map, ct_mark);
    FLOWMAP_SET(map, ct_label);

    /* Ethertype-dependent fields. */
    if (OVS_LIKELY(flow->dl_type == htons(ETH_TYPE_IP))) {
        FLOWMAP_SET(map, nw_src);
        FLOWMAP_SET(map, nw_dst);
        FLOWMAP_SET(map, nw_proto);
        FLOWMAP_SET(map, nw_frag);
        FLOWMAP_SET(map, nw_tos);
        FLOWMAP_SET(map, nw_ttl);
        FLOWMAP_SET(map, tp_src);
        FLOWMAP_SET(map, tp_dst);

        if (OVS_UNLIKELY(flow->nw_proto == IPPROTO_IGMP)) {
            FLOWMAP_SET(map, igmp_group_ip4);
        } else {
            FLOWMAP_SET(map, tcp_flags);
        }
    } else if (flow->dl_type == htons(ETH_TYPE_IPV6)) {
        FLOWMAP_SET(map, ipv6_src);
        FLOWMAP_SET(map, ipv6_dst);
        FLOWMAP_SET(map, ipv6_label);
        FLOWMAP_SET(map, nw_proto);
        FLOWMAP_SET(map, nw_frag);
        FLOWMAP_SET(map, nw_tos);
        FLOWMAP_SET(map, nw_ttl);
        FLOWMAP_SET(map, tp_src);
        FLOWMAP_SET(map, tp_dst);

        if (OVS_UNLIKELY(flow->nw_proto == IPPROTO_ICMPV6)) {
            FLOWMAP_SET(map, nd_target);
            FLOWMAP_SET(map, arp_sha);
            FLOWMAP_SET(map, arp_tha);
        } else {
            FLOWMAP_SET(map, tcp_flags);
        }
    } else if (eth_type_mpls(flow->dl_type)) {
        FLOWMAP_SET(map, mpls_lse);
    } else if (flow->dl_type == htons(ETH_TYPE_ARP) ||
               flow->dl_type == htons(ETH_TYPE_RARP)) {
        FLOWMAP_SET(map, nw_src);
        FLOWMAP_SET(map, nw_dst);
        FLOWMAP_SET(map, nw_proto);
        FLOWMAP_SET(map, arp_sha);
        FLOWMAP_SET(map, arp_tha);
    }
}
