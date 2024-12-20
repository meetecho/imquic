/*! \file   listmap.h
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Combined list and map utility (headers)
 * \details Implementation of a generic structure that contains properties
 * both of a map and a linked list (with quick pointers to the head to
 * work a bit like a queue, when appending). Mostly to be used for tracking
 * in an efficient way resources that must be ordered, but also quickly
 * accessed via a key (e.g., sent packets by packet number).
 *
 * \ingroup Core
 */

#ifndef IMQUIC_LISTMAP_H
#define IMQUIC_LISTMAP_H

#include <glib.h>

/*! \brief Type of keys for the map part, to figure out the hashing algorithm */
typedef enum imquic_listmap_key {
	/*! \brief Generic number (up to 32-bits) */
	IMQUIC_LISTMAP_NUMBER = 0,
	/*! \brief String */
	IMQUIC_LISTMAP_STRING,
	/*! \brief 64-bit number */
	IMQUIC_LISTMAP_NUMBER64,
} imquic_listmap_key;

/*! \brief Utility that implements a list and a map at the same time */
typedef struct imquic_listmap {
	/*! \brief Key type */
	imquic_listmap_key type;
	/*! \brief Linked list */
	GList *list;
	/*! \brief Current index in the list, when traversing */
	GList *index;
	/*! \brief Last item in the linked list (for appending without traversing the whole list) */
	GList *last;
	/*! \brief Hashtable to implement the map part */
	GHashTable *table;
	/*! \brief Number of items in the listmap */
	int length;
	/*! \brief Function to invoke when a stored item is removed */
	GDestroyNotify destroy;
} imquic_listmap;
/*! \brief Create a new imquic_listmap instance
 * @param type The imquic_listmap_key key type
 * @param destroy The function to invoke when a stored item is removed
 * @returns A pointer to a new imquic_listmap instance, or NULL otherwise */
imquic_listmap *imquic_listmap_create(imquic_listmap_key type, GDestroyNotify destroy);
/*! \brief Destroy an existing imquic_listmap instance
 * @param lm The imquic_listmap instance to destroy */
void imquic_listmap_destroy(imquic_listmap *lm);

/*! \brief Add a new item at the beginning of a imquic_listmap instance
 * @note Adding items to a listmap resets the traversing index
 * @param lm The imquic_listmap instance to prepend the item to
 * @param key The item key, for the map
 * @param item The item to add to the listmap
 * @returns 0 if successful, or a negative integer otherwise */
int imquic_listmap_prepend(imquic_listmap *lm, void *key, void *item);
/*! \brief Add a new item at the end of a imquic_listmap instance
 * @note Adding items to a listmap resets the traversing index
 * @param lm The imquic_listmap instance to append the item to
 * @param key The item key, for the map
 * @param item The item to add to the listmap
 * @returns 0 if successful, or a negative integer otherwise */
int imquic_listmap_append(imquic_listmap *lm, void *key, void *item);
/*! \brief Remove an item from a imquic_listmap instance
 * @note Removing items from a listmap resets the traversing index
 * @param lm The imquic_listmap instance to remove the item from
 * @param key The key of the item to remove
 * @returns 0 if successful, or a negative integer otherwise */
int imquic_listmap_remove(imquic_listmap *lm, void *key);
/*! \brief Remove all items from a imquic_listmap instance
 * @param lm The imquic_listmap instance to clear
 * @returns 0 if successful, or a negative integer otherwise */
int imquic_listmap_clear(imquic_listmap *lm);

/*! \brief Look for an item via its key
 * @param lm The imquic_listmap instance to lookup
 * @param key The item key to lookup
 * @returns A pointer to the item, if found, or NULL otherwise */
void *imquic_listmap_find(imquic_listmap *lm, void *key);
/*! \brief Check if a listmap contains a certain item
 * @param lm The imquic_listmap instance to search
 * @param item The item to find
 * @returns TRUE if found, or FALSE otherwise */
gboolean imquic_listmap_contains(imquic_listmap *lm, void *item);

/*! \brief Start traversing a listmap in an ordered way from the start
 * @note This only resets the list: use imquic_listmap_traverse_next
 * and imquic_listmap_traverse_prev to actually access the items
 * @param lm The imquic_listmap to start traversing */
void imquic_listmap_traverse(imquic_listmap *lm);
/*! \brief Get the next item from the listmap, assuming we're traversing
 * @param[in] lm The imquic_listmap to get the next item from
 * @param[out] found Set to TRUE if the item was found (to avoid ambiguities
 * if the item itself is 0 or NULL)
 * @returns A pointer to the item */
void *imquic_listmap_next(imquic_listmap *lm, gboolean *found);
/*! \brief Get the previous item from the listmap, assuming we're traversing
 * @param[in] lm The imquic_listmap to get the previous item from
 * @param[out] found Set to TRUE if the item was found (to avoid ambiguities
 * if the item itself is 0 or NULL)
 * @returns A pointer to the item */
void *imquic_listmap_prev(imquic_listmap *lm, gboolean *found);


#endif
