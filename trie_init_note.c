/* this might reveal the relationship between the "cls_subtable" and  "cls_trie" */
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
        /* ********************************************************************************************************************************************************** //
        // This prefix len is getting from the subtable's mask (struct minimask)...
        /* Compressed flow wildcards. */

        /* A sparse representation of a "struct flow_wildcards".
         *
         * See the large comment on struct miniflow for details.
         *
         * Note: While miniflow can have zero data for a 1-bit in the map,
         * a minimask may not!  We rely on this in the implementation. */

        // struct minimask {
        //     struct miniflow masks;
        // };

        /* Compressed flow. */

        /* A sparse representation of a "struct flow".
         *
         * A "struct flow" is fairly large and tends to be mostly zeros.  Sparse
         * representation has two advantages.  First, it saves memory and, more
         * importantly, minimizes the number of accessed cache lines.  Second, it saves
         * time when the goal is to iterate over only the nonzero parts of the struct.
         *
         * The map member hold one bit for each uint64_t in a "struct flow".  Each
         * 0-bit indicates that the corresponding uint64_t is zero, each 1-bit that it
         * *may* be nonzero (see below how this applies to minimasks).
         *
         * The values indicated by 'map' always follow the miniflow in memory.  The
         * user of the miniflow is responsible for always having enough storage after
         * the struct miniflow corresponding to the number of 1-bits in maps.
         *
         * Elements in values array are allowed to be zero.  This is useful for "struct
         * minimatch", for which ensuring that the miniflow and minimask members have
         * same maps allows optimization.  This allowance applies only to a miniflow
         * that is not a mask.  That is, a minimask may NOT have zero elements in its
         * values.
         *
         * A miniflow is always dynamically allocated so that the maps are followed by
         * at least as many elements as there are 1-bits in maps. */
        
        // struct miniflow {
        //     struct flowmap map;
        // };

        /* Followed by:
             *     uint64_t values[n];
             * where 'n' is miniflow_n_values(miniflow). */

        // struct flowmap {
        //     map_t bits[FLOWMAP_UNITS];
        // };

        // typedef unsigned long long map_t;

        // ****************************************************************************************************************************************************************** //

        // .. and the prefix len is related to the "field" (struct mf_field)
        

        if (plen) {
            struct cls_match *head;

            CMAP_FOR_EACH (head, cmap_node, &subtable->rules) {
                trie_insert(trie, head->cls_rule, plen);
            }
        }
        /* Initialize subtable's prefix length on this field.  This will
         * allow readers to use the trie. */
        atomic_thread_fence(memory_order_release);

        // The trie_plen is not very long, the data type is "int"
        subtable->trie_plen[trie_idx] = plen;
    }
}
