#ifndef AVL_HEADER
#define AVL_HEADER

#include "gcc-attributes.h"

/* Maximum AVL tree height. */
#ifndef AVL_MAX_HEIGHT
#define AVL_MAX_HEIGHT 92
#endif

/* Data structures */

/* One element of the AVL tree */
typedef struct avl {
    struct avl *avl_link[2];  /* Subtrees - 0 left, 1 right */
    signed char avl_balance;  /* Balance factor. */
} avl_t;

/* An AVL tree */
typedef struct avl_tree {
    avl_t *root;
    int (*compar)(void *a, void *b);
} avl_tree_t;

/* Iterator state struct */
typedef struct avl_iterator {
	avl_tree_t *tree;
	avl_t *current;
	avl_t *stack[AVL_MAX_HEIGHT];
	unsigned height;
} avl_iterator;


/* Public methods */

/* Insert element a into the AVL tree t
 * returns the added element a, or a pointer the
 * element that is equal to a (as returned by t->compar())
 * a is linked directly to the tree, so it has to
 * be properly allocated by the caller.
 */
avl_t *avl_insert(avl_tree_t *t, avl_t *a) NEVERNULL WARNUNUSED;

/* Remove an element a from the AVL tree t
 * returns a pointer to the removed element
 * or NULL if an element equal to a is not found
 * (equal as returned by t->compar())
 */
avl_t *avl_remove(avl_tree_t *t, avl_t *a) WARNUNUSED;

/* Find the element into the tree that equal to a
 * (equal as returned by t->compar())
 * returns NULL is no element is equal to a
 */
avl_t *avl_search(const avl_tree_t *t, avl_t *a);

/* Initialize the avl_tree_t
 */
void avl_init(avl_tree_t *t, int (*compar)(void *a, void *b));

/* Walk the tree and call callback at each node
 */
int avl_traverse(const avl_tree_t *t, int (*callback)(void *entry, void *data),
		 void *data);

/* Walk the tree down to the first node and return it
 */
avl_t *avl_first(avl_iterator *i, avl_tree_t *t);

/* Walk the tree to the next logical node and return it
 */
avl_t *avl_next(avl_iterator *i);

/* Given two trees, see if any in needle are contained in haystack
 */
int avl_intersection(const avl_tree_t *needle, avl_tree_t *haystack);

#endif /* avl.h */
