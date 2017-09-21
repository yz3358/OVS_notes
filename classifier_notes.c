/* A flow classifier. */
struct classifier {
    int n_rules;                    /* Total number of rules. */
    uint8_t n_flow_segments;
    uint8_t flow_segments[CLS_MAX_INDICES]; /* Flow segment boundaries to use
                                             * for staged lookup. */
    struct cmap subtables_map;      /* Contains "struct cls_subtable"s.  */
    struct pvector subtables;
    struct cmap partitions;         /* Contains "struct cls_partition"s. */
    struct cls_trie tries[CLS_MAX_TRIES]; /* Prefix tries. */
    unsigned int n_tries;
    bool publish;                   /* Make changes visible to lookups? */
};


/* Inserts 'rule' into 'cls' in 'version'.  Until 'rule' is removed from 'cls',
 * the caller must not modify or free it.
 *
 * If 'cls' already contains an identical rule (including wildcards, values of
 * fixed fields, and priority) that is visible in 'version', replaces the old
 * rule by 'rule' and returns the rule that was replaced.  The caller takes
 * ownership of the returned rule and is thus responsible for destroying it
 * with cls_rule_destroy(), after RCU grace period has passed (see
 * ovsrcu_postpone()).
 *
 * Returns NULL if 'cls' does not contain a rule with an identical key, after
 * inserting the new rule.  In this case, no rules are displaced by the new
 * rule, even rules that cannot have any effect because the new rule matches a
 * superset of their flows and has higher priority.
 */
const struct cls_rule *
classifier_replace(struct classifier *cls, const struct cls_rule *rule,
                   ovs_version_t version,
                   const struct cls_conjunction *conjs, size_t n_conjs)
{
    struct cls_match *new;
    struct cls_subtable *subtable;
    uint32_t ihash[CLS_MAX_INDICES];
    struct cls_match *head;
    unsigned int mask_offset;
    size_t n_rules = 0;
    uint32_t basis;
    uint32_t hash;
    unsigned int i;

    /* 'new' is initially invisible to lookups. */
    new = cls_match_alloc(rule, version, conjs, n_conjs);
    ovsrcu_set(&CONST_CAST(struct cls_rule *, rule)->cls_match, new);

    subtable = find_subtable(cls, rule->match.mask);
    if (!subtable) {
        subtable = insert_subtable(cls, rule->match.mask);
    }

    /* Compute hashes in segments. */
    basis = 0;
    mask_offset = 0;
    for (i = 0; i < subtable->n_indices; i++) {
        ihash[i] = minimatch_hash_range(&rule->match, subtable->index_maps[i],
                                        &mask_offset, &basis);
    }
    hash = minimatch_hash_range(&rule->match, subtable->index_maps[i],
                                &mask_offset, &basis);

    head = find_equal(subtable, rule->match.flow, hash);
    if (!head) {
        /* Add rule to tries.
         *
         * Concurrent readers might miss seeing the rule until this update,
         * which might require being fixed up by revalidation later. */
        for (i = 0; i < cls->n_tries; i++) {
            if (subtable->trie_plen[i]) {
                trie_insert(&cls->tries[i], rule, subtable->trie_plen[i]);
            }
        }

        /* Add rule to ports trie. */
        if (subtable->ports_mask_len) {
            /* We mask the value to be inserted to always have the wildcarded
             * bits in known (zero) state, so we can include them in comparison
             * and they will always match (== their original value does not
             * matter). */
            ovs_be32 masked_ports = minimatch_get_ports(&rule->match);

            trie_insert_prefix(&subtable->ports_trie, &masked_ports,
                               subtable->ports_mask_len);
        }

        /* Add new node to segment indices. */
        for (i = 0; i < subtable->n_indices; i++) {
            ccmap_inc(&subtable->indices[i], ihash[i]);
        }
        n_rules = cmap_insert(&subtable->rules, &new->cmap_node, hash);
    } else {   /* Equal rules exist in the classifier already. */
        struct cls_match *prev, *iter;

        /* Scan the list for the insertion point that will keep the list in
         * order of decreasing priority.  Insert after rules marked invisible
         * in any version of the same priority. */
        FOR_EACH_RULE_IN_LIST_PROTECTED (iter, prev, head) {
            if (rule->priority > iter->priority
                || (rule->priority == iter->priority
                    && !cls_match_is_eventually_invisible(iter))) {
                break;
            }
        }

        /* Replace 'iter' with 'new' or insert 'new' between 'prev' and
         * 'iter'. */
        if (iter) {
            struct cls_rule *old;

            if (rule->priority == iter->priority) {
                cls_match_replace(prev, iter, new);
                old = CONST_CAST(struct cls_rule *, iter->cls_rule);
            } else {
                cls_match_insert(prev, iter, new);
                old = NULL;
            }

            /* Replace the existing head in data structures, if rule is the new
             * head. */
            if (iter == head) {
                cmap_replace(&subtable->rules, &head->cmap_node,
                             &new->cmap_node, hash);
            }

            if (old) {
                struct cls_conjunction_set *conj_set;

                conj_set = ovsrcu_get_protected(struct cls_conjunction_set *,
                                                &iter->conj_set);
                if (conj_set) {
                    ovsrcu_postpone(free, conj_set);
                }

                ovsrcu_set(&old->cls_match, NULL); /* Marks old rule as removed
                                                    * from the classifier. */
                ovsrcu_postpone(cls_match_free_cb, iter);

                /* No change in subtable's max priority or max count. */

                /* Make 'new' visible to lookups in the appropriate version. */
                cls_match_set_remove_version(new, OVS_VERSION_NOT_REMOVED);

                /* Make rule visible to iterators (immediately). */
                rculist_replace(CONST_CAST(struct rculist *, &rule->node),
                                &old->node);

                /* Return displaced rule.  Caller is responsible for keeping it
                 * around until all threads quiesce. */
                return old;
            }
        } else {
            /* 'new' is new node after 'prev' */
            cls_match_insert(prev, iter, new);
        }
    }

    /* Make 'new' visible to lookups in the appropriate version. */
    cls_match_set_remove_version(new, OVS_VERSION_NOT_REMOVED);

    /* Make rule visible to iterators (immediately). */
    rculist_push_back(&subtable->rules_list,
                      CONST_CAST(struct rculist *, &rule->node));

    /* Rule was added, not replaced.  Update 'subtable's 'max_priority' and
     * 'max_count', if necessary.
     *
     * The rule was already inserted, but concurrent readers may not see the
     * rule yet as the subtables vector is not updated yet.  This will have to
     * be fixed by revalidation later. */
    if (n_rules == 1) {
        subtable->max_priority = rule->priority;
        subtable->max_count = 1;
        pvector_insert(&cls->subtables, subtable, rule->priority);
    } else if (rule->priority == subtable->max_priority) {
        ++subtable->max_count;
    } else if (rule->priority > subtable->max_priority) {
        subtable->max_priority = rule->priority;
        subtable->max_count = 1;
        pvector_change_priority(&cls->subtables, subtable, rule->priority);
    }

    /* Nothing was replaced. */
    cls->n_rules++;

    if (cls->publish) {
        pvector_publish(&cls->subtables);
    }

    return NULL;
}

/* Inserts 'rule' into 'cls'.  Until 'rule' is removed from 'cls', the caller
 * must not modify or free it.
 *
 * 'cls' must not contain an identical rule (including wildcards, values of
 * fixed fields, and priority).  Use classifier_find_rule_exactly() to find
 * such a rule. */
void
classifier_insert(struct classifier *cls, const struct cls_rule *rule,
                  ovs_version_t version, const struct cls_conjunction conj[],
                  size_t n_conj)
{
    const struct cls_rule *displaced_rule
        = classifier_replace(cls, rule, version, conj, n_conj);
    ovs_assert(!displaced_rule);
}

/* Removes 'rule' from 'cls'.  It is the caller's responsibility to destroy
 * 'rule' with cls_rule_destroy(), freeing the memory block in which 'rule'
 * resides, etc., as necessary.
 *
 * Does nothing if 'rule' has been already removed, or was never inserted.
 *
 * Returns the removed rule, or NULL, if it was already removed.
 */
const struct cls_rule *
classifier_remove(struct classifier *cls, const struct cls_rule *cls_rule)
{
    struct cls_match *rule, *prev, *next, *head;
    struct cls_conjunction_set *conj_set;
    struct cls_subtable *subtable;
    uint32_t basis = 0, hash, ihash[CLS_MAX_INDICES];
    unsigned int mask_offset;
    size_t n_rules;
    unsigned int i;

    rule = get_cls_match_protected(cls_rule);
    if (!rule) {
        return NULL;
    }
    /* Mark as removed. */
    ovsrcu_set(&CONST_CAST(struct cls_rule *, cls_rule)->cls_match, NULL);

    /* Remove 'cls_rule' from the subtable's rules list. */
    rculist_remove(CONST_CAST(struct rculist *, &cls_rule->node));

    subtable = find_subtable(cls, cls_rule->match.mask);
    ovs_assert(subtable);

    mask_offset = 0;
    for (i = 0; i < subtable->n_indices; i++) {
        ihash[i] = minimatch_hash_range(&cls_rule->match,
                                        subtable->index_maps[i],
                                        &mask_offset, &basis);
    }
    hash = minimatch_hash_range(&cls_rule->match, subtable->index_maps[i],
                                &mask_offset, &basis);

    head = find_equal(subtable, cls_rule->match.flow, hash);

    /* Check if the rule is not the head rule. */
    if (rule != head) {
        struct cls_match *iter;

        /* Not the head rule, but potentially one with the same priority. */
        /* Remove from the list of equal rules. */
        FOR_EACH_RULE_IN_LIST_PROTECTED (iter, prev, head) {
            if (rule == iter) {
                break;
            }
        }
        ovs_assert(iter == rule);

        cls_match_remove(prev, rule);

        goto check_priority;
    }

    /* 'rule' is the head rule.  Check if there is another rule to
     * replace 'rule' in the data structures. */
    next = cls_match_next_protected(rule);
    if (next) {
        cmap_replace(&subtable->rules, &rule->cmap_node, &next->cmap_node,
                     hash);
        goto check_priority;
    }

    /* 'rule' is last of the kind in the classifier, must remove from all the
     * data structures. */

    if (subtable->ports_mask_len) {
        ovs_be32 masked_ports = minimatch_get_ports(&cls_rule->match);

        trie_remove_prefix(&subtable->ports_trie,
                           &masked_ports, subtable->ports_mask_len);
    }
    for (i = 0; i < cls->n_tries; i++) {
        if (subtable->trie_plen[i]) {
            trie_remove(&cls->tries[i], cls_rule, subtable->trie_plen[i]);
        }
    }

    /* Remove rule node from indices. */
    for (i = 0; i < subtable->n_indices; i++) {
        ccmap_dec(&subtable->indices[i], ihash[i]);
    }
    n_rules = cmap_remove(&subtable->rules, &rule->cmap_node, hash);

    if (n_rules == 0) {
        destroy_subtable(cls, subtable);
    } else {
check_priority:
        if (subtable->max_priority == rule->priority
            && --subtable->max_count == 0) {
            /* Find the new 'max_priority' and 'max_count'. */
            int max_priority = INT_MIN;
            struct cls_match *head;

            CMAP_FOR_EACH (head, cmap_node, &subtable->rules) {
                if (head->priority > max_priority) {
                    max_priority = head->priority;
                    subtable->max_count = 1;
                } else if (head->priority == max_priority) {
                    ++subtable->max_count;
                }
            }
            subtable->max_priority = max_priority;
            pvector_change_priority(&cls->subtables, subtable, max_priority);
        }
    }

    if (cls->publish) {
        pvector_publish(&cls->subtables);
    }

    /* free the rule. */
    conj_set = ovsrcu_get_protected(struct cls_conjunction_set *,
                                    &rule->conj_set);
    if (conj_set) {
        ovsrcu_postpone(free, conj_set);
    }
    ovsrcu_postpone(cls_match_free_cb, rule);
    cls->n_rules--;

    return cls_rule;
}