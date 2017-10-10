static void
map_insert(odp_port_t port, struct eth_addr mac, struct in6_addr *addr,
           uint8_t nw_proto, ovs_be16 tp_port, const char dev_name[])
{
    const struct cls_rule *cr;
    struct tnl_port_in *p;
    struct match match;

    memset(&match, 0, sizeof match);
    tnl_port_init_flow(&match.flow, mac, addr, nw_proto, tp_port);

    do {
        cr = classifier_lookup(&cls, OVS_VERSION_MAX, &match.flow, NULL);
        p = tnl_port_cast(cr);
        /* Try again if the rule was released before we get the reference. */
    } while (p && !ovs_refcount_try_ref_rcu(&p->ref_cnt));

    if (!p) {
        p = xzalloc(sizeof *p);
        p->portno = port;

        match.wc.masks.dl_type = OVS_BE16_MAX;
        match.wc.masks.nw_proto = 0xff;
         /* XXX: No fragments support. */
        match.wc.masks.nw_frag = FLOW_NW_FRAG_MASK;

        /* 'tp_port' is zero for GRE tunnels. In this case it
         * doesn't make sense to match on UDP port numbers. */
        if (tp_port) {
            match.wc.masks.tp_dst = OVS_BE16_MAX;
        }
        if (IN6_IS_ADDR_V4MAPPED(addr)) {
            match.wc.masks.nw_dst = OVS_BE32_MAX;
        } else {
            match.wc.masks.ipv6_dst = in6addr_exact;
        }
        match.wc.masks.vlans[0].tci = OVS_BE16_MAX;
        memset(&match.wc.masks.dl_dst, 0xff, sizeof (struct eth_addr));

        cls_rule_init(&p->cr, &match, 0); /* Priority == 0. */
        ovs_refcount_init(&p->ref_cnt);
        ovs_strlcpy(p->dev_name, dev_name, sizeof p->dev_name);

        classifier_insert(&cls, &p->cr, OVS_VERSION_MIN, NULL, 0);
    }
}
