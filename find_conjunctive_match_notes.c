static struct conjunctive_match *
find_conjunctive_match__(struct hmap *matches, uint64_t id, uint32_t hash)
{
    struct conjunctive_match *m;

    HMAP_FOR_EACH_IN_BUCKET (m, hmap_node, hash, matches) {
        if (m->id == id) {
            return m;
        }
    }
    return NULL;
}

// find_conjunctive_match(soft[i], n_soft_pri, &matches, cm_stubs, ARRAY_SIZE(cm_stubs), &id))
// set = soft[i]    (each soft[i] is a *cls_conjunction_set, soft itself is a 2-d pointer)
// max_n_clauses = n_soft_pri   (clauses = one soft match) (those soft matches share a same priority)
// matches = &matches
// idp = id     (it is a pointer by the way...)

static bool
find_conjunctive_match(const struct cls_conjunction_set *set,
                       unsigned int max_n_clauses, struct hmap *matches,
                       struct conjunctive_match *cm_stubs, size_t n_cm_stubs,
                       uint32_t *idp)
{
    const struct cls_conjunction *c;

    // if the n_soft_pri is smaller than the Smallest 'n' among elements of 'conj', then this soft match is illegal

    /*
     * Each cls_conjunction_set has a 'n' and a 'min_n_clauses', because each element
     * in this cls_conjunction_set can belongs to different sets (one element can have
     * multiple conjunctive actions)
     */
    if (max_n_clauses < set->min_n_clauses) {
        return false;
    }

    // The conj is an (pointer of) array, with elements that are cls_conjunction
    // This loop iterates through those cls_conjunction (the struct cls_conjunction is confusing ...)
    for (c = set->conj; c < &set->conj[set->n]; c++) {
        struct conjunctive_match *cm;
        uint32_t hash;

        // this cls_conjunction part of a set that is too large, thus we cannot use this
        if (c->n_clauses > max_n_clauses) {
            continue;
        }

        // based on id
        hash = hash_int(c->id, 0);

        // cm is a conjunctive_match
        cm = find_conjunctive_match__(matches, c->id, hash);

        // find nothing..
        if (!cm) {
            size_t n = hmap_count(matches);
            cm = n < n_cm_stubs ? &cm_stubs[n] : xmalloc(sizeof *cm);
            hmap_insert(matches, &cm->hmap_node, hash);
            cm->id = c->id;
            cm->clauses = UINT64_MAX << (c->n_clauses & 63);
        }


        cm->clauses |= UINT64_C(1) << c->clause;
        if (cm->clauses == UINT64_MAX) {
            *idp = cm->id;
            return true;
        }
    }
    return false;
}
