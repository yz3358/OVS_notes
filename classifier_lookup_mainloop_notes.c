

/* Main loop. */
struct cls_subtable *subtable;

/* Loop while priority is higher than or equal to 'PRIORITY = hard_pri+1' (hard_pri initially INT_MIN)
 * and prefetch objects of size 'SZ = sizeof *subtable' (which means we are fetching subtable from "subtables")
 * 'N = 2' objects ahead from the current object. (why fetch 2 ahead??)
 * The "subtable" is the pointer itself, which iterates the whole thing.
 * It is assigned to a new subtable every loop.
 */
PVECTOR_FOR_EACH_PRIORITY (subtable, hard_pri + 1, 2, sizeof *subtable,
                           &cls->subtables) {
// ...
}

// &cls->subtables is a pvector
/* Concurrent priority vector. */
struct pvector {
    OVSRCU_TYPE(struct pvector_impl *) impl;
    struct pvector_impl *temp;
};

struct pvector_impl {
    size_t size;       /* Number of entries in the vector. */
    size_t allocated;  /* Number of allocated entries. */
    struct pvector_entry vector[];
};

struct pvector_entry {
    int priority;
    void *ptr;
};
// The priority is bound with the pvector "subtables", and must be pre assigned at some point before here.

/* Loop while priority is higher than or equal to 'PRIORITY' and prefetch
 * objects of size 'SZ' 'N' objects ahead from the current object. */
#define PVECTOR_FOR_EACH_PRIORITY(PTR, PRIORITY, N, SZ, PVECTOR)        \
    for (struct pvector_cursor cursor__ = pvector_cursor_init(PVECTOR, N, SZ); \
         ((PTR) = pvector_cursor_next(&cursor__, PRIORITY, N, SZ)) != NULL; )
