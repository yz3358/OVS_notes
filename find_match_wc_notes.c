// This find match is based on a pre-generated wildcard and was performed on subtables

static const struct cls_match *
find_match_wc(const struct cls_subtable *subtable, ovs_version_t version,
              const struct flow *flow, struct trie_ctx trie_ctx[CLS_MAX_TRIES],
              unsigned int n_tries, struct flow_wildcards *wc)
{
    // this is very unlikely to happen
    if (OVS_UNLIKELY(!wc)) {
        return find_match(subtable, version, flow,
                          flow_hash_in_minimask(flow, &subtable->mask, 0));
    }

    uint32_t basis = 0, hash;
    const struct cls_match *rule = NULL;
    struct flowmap stages_map = FLOWMAP_EMPTY_INITIALIZER;
    unsigned int mask_offset = 0;
    int i;

    /* Try to finish early by checking fields in segments. */
    // skip skip skip
    for (i = 0; i < subtable->n_indices; i++) {
        if (check_tries(trie_ctx, n_tries, subtable->trie_plen,
                        subtable->index_maps[i], flow, wc)) {
            /* 'wc' bits for the trie field set, now unwildcard the preceding
             * bits used so far. */

            // THIS check_tries will ...
            /* Return 'true' if can skip rest of the subtable based on the prefix trie
             * lookup results. */
            goto no_match;
        }

        /* Accumulate the map used so far. */
        // The map is used only when no match found, at the end of this func
        stages_map = flowmap_or(stages_map, subtable->index_maps[i]);

        hash = flow_hash_in_minimask_range(flow, &subtable->mask,
                                           subtable->index_maps[i],
                                           &mask_offset, &basis);

        if (!ccmap_find(&subtable->indices[i], hash)) {
            goto no_match;
        }
    }


    /* Trie check for the final range. */
    // No need for stages_map accumulation in the final round
    if (check_tries(trie_ctx, n_tries, subtable->trie_plen,
                    subtable->index_maps[i], flow, wc)) {
        goto no_match;
    }
    hash = flow_hash_in_minimask_range(flow, &subtable->mask,
                                       subtable->index_maps[i],
                                       &mask_offset, &basis);

    // the rule is found based on the hash value
    rule = find_match(subtable, version, flow, hash);

    // if this rule was not found and subtable's ports_mask_len was not 0
    // ports_mask_len is relating to the "FINAL STAGE"
    if (!rule && subtable->ports_mask_len) {
        /* The final stage had ports, but there was no match.  Instead of
         * unwildcarding all the ports bits, use the ports trie to figure out a
         * smaller set of bits to unwildcard. */
        unsigned int mbits;
        ovs_be32 value, plens, mask;

        mask = MINIFLOW_GET_BE32(&subtable->mask.masks, tp_src);
        value = ((OVS_FORCE ovs_be32 *)flow)[TP_PORTS_OFS32] & mask;
        mbits = trie_lookup_value(&subtable->ports_trie, &value, &plens, 32);

        ((OVS_FORCE ovs_be32 *)&wc->masks)[TP_PORTS_OFS32] |=
            mask & be32_prefix_mask(mbits);

        goto no_match;
    }

    /* Must unwildcard all the fields, as they were looked at. */
    flow_wildcards_fold_minimask(wc, &subtable->mask);
    return rule;

no_match:
    /* Unwildcard the bits in stages so far, as they were used in determining
     * there is no match. */
    // does this update anything?
    flow_wildcards_fold_minimask_in_map(wc, &subtable->mask, stages_map);
    return NULL;
}
