/* Like classifier_lookup(), except that support for conjunctive matches can be
 * configured with 'allow_conjunctive_matches'.  That feature is not exposed
 * externally because turning off conjunctive matches is only useful to avoid
 * recursion within this function itself.
 *
 * 'flow' is non-const to allow for temporary modifications during the lookup.
 * The 'flow' is modified when performing soft match
 * Any changes are restored before returning. */
static const struct cls_rule *
classifier_lookup__(const struct classifier *cls, ovs_version_t version,
                    struct flow *flow, struct flow_wildcards *wc,
                    bool allow_conjunctive_matches)
{
    struct trie_ctx trie_ctx[CLS_MAX_TRIES];
    const struct cls_match *match;
    /* Highest-priority flow in 'cls' that certainly matches 'flow'. */
    const struct cls_match *hard = NULL;
    int hard_pri = INT_MIN;     /* hard ? hard->priority : INT_MIN. */

    /* Highest-priority conjunctive flows in 'cls' matching 'flow'.  Since
     * these are (components of) conjunctive flows, we can only know whether
     * the full conjunctive flow matches after seeing multiple of them.  Thus,
     * we refer to these as "soft matches". */
    struct cls_conjunction_set *soft_stub[64];
    struct cls_conjunction_set **soft = soft_stub;
    size_t n_soft = 0, allocated_soft = ARRAY_SIZE(soft_stub);
    int soft_pri = INT_MIN;    /* n_soft ? MAX(soft[*]->priority) : INT_MIN. */

    /* Synchronize for cls->n_tries and subtable->trie_plen.  They can change
     * when table configuration changes, which happens typically only on
     * startup. */
    atomic_thread_fence(memory_order_acquire);

    /* Initialize trie contexts for find_match_wc(). */
    for (int i = 0; i < cls->n_tries; i++) {
        trie_ctx_init(&trie_ctx[i], &cls->tries[i]);
    }

    /* Main loop. */
    struct cls_subtable *subtable;

    /* Loop while priority is higher than or equal to 'PRIORITY = hard_pri+1' (hard_pri initially INT_MIN)
     * and prefetch objects of size 'SZ = sizeof *subtable' (which means we are fetching subtable from "subtables")
     * 'N = 2' objects ahead from the current object. (why fetch 2 ahead??)
     * The "subtable" is the pointer itself, which iterates the whole thing.
     * It is assigned to a new subtable every loop.
     */
     // every subtable was bound to a priority, the max_priority of all rules in that subtable
     // in every subtable, rules have different priority
     // thus every match has its unique priority
    PVECTOR_FOR_EACH_PRIORITY (subtable, hard_pri + 1, 2, sizeof *subtable,
                               &cls->subtables) {
        struct cls_conjunction_set *conj_set;

        /* Skip subtables with no match, or where the match is lower-priority
         * than some certain match we've already found. */

        /*
        * static const struct cls_match *
        * find_match_wc(
        * const struct cls_subtable *subtable = "a pointer iterates through the loop, pointing to 1 subtable",
        * ovs_version_t version = "just a version id",
        * const struct flow *flow,
        * struct trie_ctx trie_ctx[CLS_MAX_TRIES] = 'copied from the classifier',
        * unsigned int n_tries,
        * struct flow_wildcards *wc = 'specified by some unwildcarding func')
        */

        match = find_match_wc(subtable, version, flow, trie_ctx, cls->n_tries,
                              wc);
        if (!match || match->priority <= hard_pri) {
            continue; // skip this subtable for this priority
        }


        // at this point, a match was found and the priority is higher than the hard_pri
        // this might or might not be part of a conjunctive_match
        conj_set = ovsrcu_get(struct cls_conjunction_set *, &match->conj_set);
        if (!conj_set) {
            /* 'match' isn't part of a conjunctive match.  It's the best
             * certain match we've got so far, since we know that it's
             * higher-priority than hard_pri.
             *
             * (There might be a higher-priority conjunctive match.  We can't
             * tell yet.) */
            hard = match;
            hard_pri = hard->priority;
        }
        else if (allow_conjunctive_matches) {
            /* 'match' is part of a conjunctive match.  Add it to the list. */
            // part of a conjunctive match???

            if (OVS_UNLIKELY(n_soft >= allocated_soft)) {
                struct cls_conjunction_set **old_soft = soft;

                allocated_soft *= 2;
                soft = xmalloc(allocated_soft * sizeof *soft);
                memcpy(soft, old_soft, n_soft * sizeof *soft);
                if (old_soft != soft_stub) {
                    free(old_soft);
                }
            }
            soft[n_soft++] = conj_set;

            /* Keep track of the highest-priority soft match. */
            if (soft_pri < match->priority) {
                soft_pri = match->priority;
            }
        }
    }


    /* In the common case, at this point we have no soft matches and we can
     * return immediately.  (We do the same thing if we have potential soft
     * matches but none of them are higher-priority than our hard match.) */
    if (hard_pri >= soft_pri) {
        if (soft != soft_stub) {
            free(soft);
        }
        return hard ? hard->cls_rule : NULL;
    }


    /* At this point, we have some soft matches.  We might also have a hard
     * match; if so, its priority is lower than the highest-priority soft
     * match. */

    /* Soft match loop.
     *
     * Check whether soft matches are real matches. */
    for (;;) {
        /* Delete soft matches that are null.  This only happens in second and
         * subsequent iterations of the soft match loop, when we drop back from
         * a high-priority soft match to a lower-priority one.
         *
         * Also, delete soft matches whose priority is less than or equal to
         * the hard match's priority.  In the first iteration of the soft
         * match, these can be in 'soft' because the earlier main loop found
         * the soft match before the hard match.  In second and later iteration
         * of the soft match loop, these can be in 'soft' because we dropped
         * back from a high-priority soft match to a lower-priority soft match.
         *
         * It is tempting to delete soft matches that cannot be satisfied
         * because there are fewer soft matches than required to satisfy any of
         * their conjunctions, but we cannot do that because there might be
         * lower priority soft or hard matches with otherwise identical
         * matches.  (We could special case those here, but there's no
         * need--we'll do so at the bottom of the soft match loop anyway and
         * this duplicates less code.)
         *
         * It's also tempting to break out of the soft match loop if 'n_soft ==
         * 1' but that would also miss lower-priority hard matches.  We could
         * special case that also but again there's no need. */
        for (int i = 0; i < n_soft; ) {
            if (!soft[i] || soft[i]->priority <= hard_pri) {
                soft[i] = soft[--n_soft];
            } else {
                i++;
            }
        }
        if (!n_soft) {
            break;
        }

        /* Find the highest priority among the soft matches.  (We know this
         * must be higher than the hard match's priority; otherwise we would
         * have deleted all of the soft matches in the previous loop.)  Count
         * the number of soft matches that have that priority. */
        soft_pri = INT_MIN;
        int n_soft_pri = 0;
        for (int i = 0; i < n_soft; i++) {
            if (soft[i]->priority > soft_pri) {
                soft_pri = soft[i]->priority;
                n_soft_pri = 1;
                // find a soft priority was bigger than the current max
                // update and n_soft_pri = 1, makes sense
            } else if (soft[i]->priority == soft_pri) {
                n_soft_pri++;
            }
        }
        ovs_assert(soft_pri > hard_pri);

        /* Look for a real match among the highest-priority soft matches.
         *
         * It's unusual to have many conjunctive matches, so we use stubs to
         * avoid calling malloc() in the common case.  An hmap has a built-in
         * stub for up to 2 hmap_nodes; possibly, we would benefit a variant
         * with a bigger stub. */
        struct conjunctive_match cm_stubs[16];
        struct hmap matches;

        hmap_init(&matches);
        for (int i = 0; i < n_soft; i++) {
            uint32_t id;

            // find_conjunctive_match returns a bool, indices whether u can find the match or not, it doesn't return an exact matched rule or any action, very unintuitive
            if (soft[i]->priority == soft_pri
                && find_conjunctive_match(soft[i], n_soft_pri, &matches,
                                          cm_stubs, ARRAY_SIZE(cm_stubs),
                                          &id)) {

                uint32_t saved_conj_id = flow->conj_id;
                const struct cls_rule *rule;

                // the context of this (id) pointer pointed area was changed during "find_conjunctive_match"
                flow->conj_id = id;

                // this rule was found with a new flow with modified id (modified by find_conjunctive_match())
                // this id is only a temp ip
                // also notice that, now allow_conjunctive_matches is set to false
                // this means the new rule should be found in hard match
                // specifically, by find_match_wc function, which generate the result based on hash value of the flow, and the hash value now was changed
                rule = classifier_lookup__(cls, version, flow, wc, false);
                flow->conj_id = saved_conj_id; // id might changed during classifier_lookup__, restore the id incase of mistake

                if (rule) {
                    free_conjunctive_matches(&matches,
                                             cm_stubs, ARRAY_SIZE(cm_stubs));
                    if (soft != soft_stub) {
                        free(soft);
                    }
                    return rule; // hard match found with legal approach
                }
            }
        }
        free_conjunctive_matches(&matches, cm_stubs, ARRAY_SIZE(cm_stubs));


        // WHAT IS THIS?
        /* There's no real match among the highest-priority soft matches.
         *
         * However, if any of those soft matches has a lower-priority but
         * otherwise identical flow match, then we need to consider those for
         * soft or hard matches.
         *
         * The next iteration of the soft match loop will delete any null
         * pointers we put into 'soft' (and some others too). */
        for (int i = 0; i < n_soft; i++) {

            // soft_pri is still the max priority of all soft matches, yet it is smaller than the hard_pri
            if (soft[i]->priority != soft_pri) {
                continue;
            }


            /* Find next-lower-priority flow with identical flow match. */
            /* Return the next visible (lower-priority) rule in the list.  Multiple
             * identical rules with the same priority may exist transitionally, but when
             * versioning is used at most one of them is ever visible for lookups on any
             * given 'version'. */
            // each match might has an equal but lower-priority match (one of the fields in the "cls_match")
            match = next_visible_rule_in_list(soft[i]->match, version);
            if (match) {

                // read the conj_set of the match
                soft[i] = ovsrcu_get(struct cls_conjunction_set *,
                                     &match->conj_set);

                // if this conj_set is NULL, means its a hard match
                if (!soft[i]) {
                    /* The flow is a hard match; don't treat as a soft
                     * match. */
                    if (match->priority > hard_pri) {
                        hard = match;
                        hard_pri = hard->priority;
                    }
                }
            } else {
                /* No such lower-priority flow (probably the common case). */
                soft[i] = NULL;
            }
        }
    }

    if (soft != soft_stub) {
        free(soft);
    }
    return hard ? hard->cls_rule : NULL;
}

/* Finds and returns the highest-priority rule in 'cls' that matches 'flow' and
 * that is visible in 'version'.  Returns a null pointer if no rules in 'cls'
 * match 'flow'.  If multiple rules of equal priority match 'flow', returns one
 * arbitrarily.
 *
 * If a rule is found and 'wc' is non-null, bitwise-OR's 'wc' with the
 * set of bits that were significant in the lookup.  At some point
 * earlier, 'wc' should have been initialized (e.g., by
 * flow_wildcards_init_catchall()).
 *
 * 'flow' is non-const to allow for temporary modifications during the lookup.
 * Any changes are restored before returning. */
const struct cls_rule *
classifier_lookup(const struct classifier *cls, ovs_version_t version,
                  struct flow *flow, struct flow_wildcards *wc)
{
    return classifier_lookup__(cls, version, flow, wc, true);
}
