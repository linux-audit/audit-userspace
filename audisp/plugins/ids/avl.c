#include "config.h"
#include <stddef.h> // for NULL
#include "avl.h"

// Note: this file is based on this:
//	 https://github.com/firehol/netdata/blob/master/src/avl.c
//	 c63bdb5 on Oct 23, 2017
//
//       which has been moved to here (05/23/20):
//       https://github.com/netdata/netdata/blob/master/libnetdata/avl/avl.c
//
// However, its been modified to remove pthreads as this application will
// only use it from a single thread.

/* ------------------------------------------------------------------------- */
/*
 * avl_insert(), avl_remove() and avl_search()
 * are adaptations (by Costa Tsaousis) of the AVL algorithm found in libavl
 * v2.0.3, so that they do not use any memory allocations and their memory
 * footprint is optimized (by eliminating non-necessary data members).
 *
 * libavl - library for manipulation of binary trees.
 * Copyright (C) 1998, 1999, 2000, 2001, 2002, 2004 Free Software
 * Foundation, Inc.
 * GNU Lesser General Public License
*/


/* Search |tree| for an item matching |item|, and return it if found.
     Otherwise return |NULL|. */
avl_t *avl_search(const avl_tree_t *tree, avl_t *item) {
    avl_t *p;

    // assert (tree != NULL && item != NULL);

    for (p = tree->root; p != NULL; ) {
        int cmp = tree->compar(item, p);

        if (cmp < 0)
            p = p->avl_link[0];
        else if (cmp > 0)
            p = p->avl_link[1];
        else /* |cmp == 0| */
            return p;
    }

    return NULL;
}

/* Inserts |item| into |tree| and returns a pointer to |item|'s address.
     If a duplicate item is found in the tree,
     returns a pointer to the duplicate without inserting |item|.
 */
avl_t *avl_insert(avl_tree_t *tree, avl_t *item) {
    avl_t *y, *z; /* Top node to update balance factor, and parent. */
    avl_t *p, *q; /* Iterator, and parent. */
    avl_t *n;     /* Newly inserted node. */
    avl_t *w;     /* New root of rebalanced subtree. */
    unsigned char dir; /* Direction to descend. */

    unsigned char da[AVL_MAX_HEIGHT]; /* Cached comparison results. */
    int k = 0;              /* Number of cached results. */

    // assert(tree != NULL && item != NULL);

    z = (avl_t *) &tree->root;
    y = tree->root;
    dir = 0;
    for (q = z, p = y; p != NULL; q = p, p = p->avl_link[dir]) {
        int cmp = tree->compar(item, p);
        if (cmp == 0)
            return p;

        if (p->avl_balance != 0)
            z = q, y = p, k = 0;
        da[k++] = dir = (cmp > 0);
    }

    n = q->avl_link[dir] = item;

    // tree->avl_count++;
    n->avl_link[0] = n->avl_link[1] = NULL;
    n->avl_balance = 0;
    if (y == NULL) return n;

    for (p = y, k = 0; p != n; p = p->avl_link[da[k]], k++)
        if (da[k] == 0)
            p->avl_balance--;
        else
            p->avl_balance++;

    if (y->avl_balance == -2) {
        avl_t *x = y->avl_link[0];
        if (x->avl_balance == -1) {
            w = x;
            y->avl_link[0] = x->avl_link[1];
            x->avl_link[1] = y;
            x->avl_balance = y->avl_balance = 0;
        }
        else {
            // assert (x->avl_balance == +1);
            w = x->avl_link[1];
            x->avl_link[1] = w->avl_link[0];
            w->avl_link[0] = x;
            y->avl_link[0] = w->avl_link[1];
            w->avl_link[1] = y;
            if (w->avl_balance == -1)
                x->avl_balance = 0, y->avl_balance = +1;
            else if (w->avl_balance == 0)
                x->avl_balance = y->avl_balance = 0;
            else /* |w->avl_balance == +1| */
                x->avl_balance = -1, y->avl_balance = 0;
            w->avl_balance = 0;
        }
    }
    else if (y->avl_balance == +2) {
        avl_t *x = y->avl_link[1];
        if (x->avl_balance == +1) {
            w = x;
            y->avl_link[1] = x->avl_link[0];
            x->avl_link[0] = y;
            x->avl_balance = y->avl_balance = 0;
        }
        else {
            // assert (x->avl_balance == -1);
            w = x->avl_link[0];
            x->avl_link[0] = w->avl_link[1];
            w->avl_link[1] = x;
            y->avl_link[1] = w->avl_link[0];
            w->avl_link[0] = y;
            if (w->avl_balance == +1)
                x->avl_balance = 0, y->avl_balance = -1;
            else if (w->avl_balance == 0)
                x->avl_balance = y->avl_balance = 0;
            else /* |w->avl_balance == -1| */
                x->avl_balance = +1, y->avl_balance = 0;
            w->avl_balance = 0;
        }
    }
    else return n;

    z->avl_link[y != z->avl_link[0]] = w;

    // tree->avl_generation++;
    return n;
}

/* Deletes from |tree| and returns an item matching |item|.
     Returns a null pointer if no matching item found. */
avl_t *avl_remove(avl_tree_t *tree, avl_t *item) {
    /* Stack of nodes. */
    avl_t *pa[AVL_MAX_HEIGHT]; /* Nodes. */
    unsigned char da[AVL_MAX_HEIGHT];    /* |avl_link[]| indexes. */
    int k;                               /* Stack pointer. */

    avl_t *p;   /* Traverses tree to find node to delete. */
    int cmp;              /* Result of comparison between |item| and |p|. */

    // assert (tree != NULL && item != NULL);

    k = 0;
    p = (avl_t *) &tree->root;
    for(cmp = -1; cmp != 0; cmp = tree->compar(item, p)) {
        unsigned char dir = (unsigned char)(cmp > 0);

        pa[k] = p;
        da[k++] = dir;

        p = p->avl_link[dir];
        if(p == NULL) return NULL;
    }

    item = p;

    if (p->avl_link[1] == NULL)
        pa[k - 1]->avl_link[da[k - 1]] = p->avl_link[0];
    else {
        avl_t *r = p->avl_link[1];
        if (r->avl_link[0] == NULL) {
            r->avl_link[0] = p->avl_link[0];
            r->avl_balance = p->avl_balance;
            pa[k - 1]->avl_link[da[k - 1]] = r;
            da[k] = 1;
            pa[k++] = r;
        }
        else {
            avl_t *s;
            int j = k++;

            for (;;) {
                da[k] = 0;
                pa[k++] = r;
                s = r->avl_link[0];
                if (s->avl_link[0] == NULL) break;

                r = s;
            }

            s->avl_link[0] = p->avl_link[0];
            r->avl_link[0] = s->avl_link[1];
            s->avl_link[1] = p->avl_link[1];
            s->avl_balance = p->avl_balance;

            pa[j - 1]->avl_link[da[j - 1]] = s;
            da[j] = 1;
            pa[j] = s;
        }
    }

    // assert (k > 0);
    while (--k > 0) {
        avl_t *y = pa[k];

        if (da[k] == 0) {
            y->avl_balance++;
            if (y->avl_balance == +1) break;
            else if (y->avl_balance == +2) {
                avl_t *x = y->avl_link[1];
                if (x->avl_balance == -1) {
                    avl_t *w;
                    // assert (x->avl_balance == -1);
                    w = x->avl_link[0];
                    x->avl_link[0] = w->avl_link[1];
                    w->avl_link[1] = x;
                    y->avl_link[1] = w->avl_link[0];
                    w->avl_link[0] = y;
                    if (w->avl_balance == +1)
                        x->avl_balance = 0, y->avl_balance = -1;
                    else if (w->avl_balance == 0)
                        x->avl_balance = y->avl_balance = 0;
                    else /* |w->avl_balance == -1| */
                        x->avl_balance = +1, y->avl_balance = 0;
                    w->avl_balance = 0;
                    pa[k - 1]->avl_link[da[k - 1]] = w;
                }
                else {
                    y->avl_link[1] = x->avl_link[0];
                    x->avl_link[0] = y;
                    pa[k - 1]->avl_link[da[k - 1]] = x;
                    if (x->avl_balance == 0) {
                        x->avl_balance = -1;
                        y->avl_balance = +1;
                        break;
                    }
                    else x->avl_balance = y->avl_balance = 0;
                }
            }
        }
        else
        {
            y->avl_balance--;
            if (y->avl_balance == -1) break;
            else if (y->avl_balance == -2) {
                avl_t *x = y->avl_link[0];
                if (x->avl_balance == +1) {
                    avl_t *w;
                    // assert (x->avl_balance == +1);
                    w = x->avl_link[1];
                    x->avl_link[1] = w->avl_link[0];
                    w->avl_link[0] = x;
                    y->avl_link[0] = w->avl_link[1];
                    w->avl_link[1] = y;
                    if (w->avl_balance == -1)
                        x->avl_balance = 0, y->avl_balance = +1;
                    else if (w->avl_balance == 0)
                        x->avl_balance = y->avl_balance = 0;
                    else /* |w->avl_balance == +1| */
                        x->avl_balance = -1, y->avl_balance = 0;
                    w->avl_balance = 0;
                    pa[k - 1]->avl_link[da[k - 1]] = w;
                }
                else {
                    y->avl_link[0] = x->avl_link[1];
                    x->avl_link[1] = y;
                    pa[k - 1]->avl_link[da[k - 1]] = x;
                    if (x->avl_balance == 0) {
                        x->avl_balance = +1;
                        y->avl_balance = -1;
                        break;
                    }
                    else x->avl_balance = y->avl_balance = 0;
                }
            }
        }
    }

    // tree->avl_count--;
    // tree->avl_generation++;
    return item;
}

/* ------------------------------------------------------------------------- */
// below are functions by (C) Costa Tsaousis

// ---------------------------
// traversing

int avl_walker(avl_t *node, int (*callback)(void *entry, void *data), void *data) {
    int total = 0, ret = 0;

    if(node->avl_link[0]) {
        ret = avl_walker(node->avl_link[0], callback, data);
        if(ret < 0) return ret;
        total += ret;
    }

    ret = callback(node, data);
    if(ret < 0) return ret;
    total += ret;

    if(node->avl_link[1]) {
        ret = avl_walker(node->avl_link[1], callback, data);
        if (ret < 0) return ret;
        total += ret;
    }

    return total;
}

int avl_traverse(const avl_tree_t *t, int (*callback)(void *entry, void *data),
                 void *data) {
    if(t->root)
        return avl_walker(t->root, callback, data);
    else
        return 0;
}

void avl_init(avl_tree_t *t, int (*compar)(void *a, void *b)) {
    t->root = NULL;
    t->compar = compar;
}

/* ------------------------------------------------------------------------- */
// below are functions by (C) Steve Grubb

// ---------------------------

avl_t *avl_first(avl_iterator *i, avl_tree_t *t)
{
	if (t->root == NULL || i == NULL)
		return NULL;

	i->tree = t;
	i->height = 0;

	// follow the leftmost node to its bottom
	avl_t *node = t->root;
	while (node->avl_link[0]) {
		i->stack[i->height] = node;
		i->height++;
		node = node->avl_link[0];
	}

	i->current = node;
	return node;
}

avl_t *avl_next(avl_iterator *i)
{
	if (i == NULL || i->tree == NULL)
		return NULL;

	avl_t *node = i->current;
	if (node == NULL)
		return avl_first(i, i->tree);
	else if (node->avl_link[1]) {
		i->stack[i->height] = node;
		i->height++;
		node = node->avl_link[1];

		while (node->avl_link[0]) {
			i->stack[i->height] = node;
			i->height++;
			node = node->avl_link[0];
		}
	} else {
		avl_t *tmp;

		do {
			if (i->height == 0) {
				i->current = NULL;
				return NULL;
			}

			tmp = node;
			i->height--;
			node = i->stack[i->height];
		} while (tmp == node->avl_link[1]);
	}

	i->current = node;
	return node;
}

static int avl_walker2(avl_t *node, avl_tree_t *haystack) {
    int ret;

    // If the lefthand has a link, take it so that we walk to the
    // leftmost bottom
    if(node->avl_link[0]) {
        ret = avl_walker2(node->avl_link[0], haystack);
        if (ret) return ret;
    }

    // Next, check the current node
    avl_t *res = avl_search(haystack, node);
    if (res) return 1;

    // If the righthand has a link, take it so that we check all the
    // rightmost nodes, too.
    if(node->avl_link[1]) {
        ret = avl_walker2(node->avl_link[1], haystack);
        if (ret) return ret;
    }

    // nothing found
    return 0;
}

int avl_intersection(const avl_tree_t *needle, avl_tree_t *haystack)
{
	// traverse the needle and search the haystack
	// this implies that needle should be smaller than haystack
	if (needle && haystack && needle->root && haystack->root)
		return avl_walker2(needle->root, haystack);

	// something is not initialized, so we cannot search
	return 0;
}
