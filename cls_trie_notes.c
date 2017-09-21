/* Prefix trie for a 'field' */
struct cls_trie {
    const struct mf_field *field; /* Trie field, or NULL. */
    rcu_trie_ptr root;            /* NULL if none. */
};

// This is the main part of 'cls_trie'
struct mf_field {
    /* Identification. */
    enum mf_field_id id;        /* MFF_*. */
    const char *name;           /* Name of this field, e.g. "eth_type". */
    const char *extra_name;     /* Alternate name, e.g. "dl_type", or NULL. */

    /* Size.
     *
     * Most fields have n_bytes * 8 == n_bits.  There are a few exceptions:
     *
     *     - "dl_vlan" is 2 bytes but only 12 bits.
     *     - "dl_vlan_pcp" is 1 byte but only 3 bits.
     *     - "is_frag" is 1 byte but only 2 bits.
     *     - "ipv6_label" is 4 bytes but only 20 bits.
     *     - "mpls_label" is 4 bytes but only 20 bits.
     *     - "mpls_tc"    is 1 byte but only 3 bits.
     *     - "mpls_bos"   is 1 byte but only 1 bit.
     */
    unsigned int n_bytes;       /* Width of the field in bytes. */
    unsigned int n_bits;        /* Number of significant bits in field. */
    bool variable_len;          /* Length is variable, if so width is max. */

    /* Properties. */
    enum mf_maskable maskable;
    enum mf_string string;
    enum mf_prereqs prereqs;
    bool writable;              /* May be written by actions? */
    bool mapped;                /* Variable length mf_field is mapped. */

    /* Usable protocols.
     *
     * NXM and OXM are extensible, allowing later extensions to be sent in
     * earlier protocol versions, so this does not necessarily correspond to
     * the OpenFlow protocol version the field was introduced in.
     * Also, some field types are tranparently mapped to each other via the
     * struct flow (like vlan and dscp/tos fields), so each variant supports
     * all protocols.
     *
     * These are combinations of OFPUTIL_P_*.  (They are not declared as type
     * enum ofputil_protocol because that would give meta-flow.h and ofp-util.h
     * a circular dependency.) */
    uint32_t usable_protocols_exact;   /* Matching or setting whole field. */
    uint32_t usable_protocols_cidr;    /* Matching a CIDR mask in field. */
    uint32_t usable_protocols_bitwise; /* Matching arbitrary bits in field. */

    int flow_be32ofs;  /* Field's be32 offset in "struct flow", if prefix tree
                        * lookup is supported for the field, or -1. */
};

/*
 * Functions for cls_trie (behavior)
 */

// initiate the trie
static void
trie_init(struct classifier *cls, int trie_idx, const struct mf_field *field)
{
    struct cls_trie *trie = &cls->tries[trie_idx];
    struct cls_subtable *subtable;

    if (trie_idx < cls->n_tries) {
        trie_destroy(&trie->root);
    } else {
        ovsrcu_set_hidden(&trie->root, NULL);
    }
    trie->field = field;

    /* Add existing rules to the new trie. */
    CMAP_FOR_EACH (subtable, cmap_node, &cls->subtables_map) {
        unsigned int plen;

        plen = field ? minimask_get_prefix_len(&subtable->mask, field) : 0;
        if (plen) {
            struct cls_match *head;

            CMAP_FOR_EACH (head, cmap_node, &subtable->rules) {
                trie_insert(trie, head->cls_rule, plen);
            }
        }
        /* Initialize subtable's prefix length on this field.  This will
         * allow readers to use the trie. */
        atomic_thread_fence(memory_order_release);
        subtable->trie_plen[trie_idx] = plen;
    }
}

// 