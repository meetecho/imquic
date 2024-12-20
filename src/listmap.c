/*! \file   listmap.c
 * \author Lorenzo Miniero <lorenzo@meetecho.com>
 * \copyright MIT License
 * \brief  Combined list and map utility
 * \details Implementation of a generic structure that contains properties
 * both of a map and a linked list (with quick pointers to the head to
 * work a bit like a queue, when appending). Mostly to be used for tracking
 * in an efficient way resources that must be ordered, but also quickly
 * accessed via a key (e.g., sent packets by packet number).
 *
 * \ingroup Core
 */

#include <stdint.h>

#include "internal/listmap.h"
#include "internal/utils.h"
#include "imquic/debug.h"

/* Create a new listmap */
imquic_listmap *imquic_listmap_create(imquic_listmap_key type, GDestroyNotify destroy) {
	imquic_listmap *lm = g_malloc(sizeof(imquic_listmap));
	lm->type = type;
	lm->list = lm->index = lm->last = NULL;
	if(type == IMQUIC_LISTMAP_NUMBER) {
		lm->table = g_hash_table_new_full(NULL, NULL, NULL, destroy);
	} else if(type == IMQUIC_LISTMAP_STRING) {
		lm->table = g_hash_table_new_full(g_str_hash, g_str_equal, (GDestroyNotify)g_free, destroy);
	} else if(type == IMQUIC_LISTMAP_NUMBER64) {
		lm->table = g_hash_table_new_full(g_int64_hash, g_int64_equal, (GDestroyNotify)g_free, destroy);
	} else {
		IMQUIC_LOG(IMQUIC_LOG_ERR, "Invalid listmap key type\n");
		g_free(lm);
		return NULL;
	}
	lm->length = 0;
	lm->destroy = destroy;
	return lm;
}

/* Destroy a listmap */
void imquic_listmap_destroy(imquic_listmap *lm) {
	if(lm != NULL) {
		if(lm->list != NULL)
			g_list_free(lm->list);
		if(lm->table != NULL)
			g_hash_table_unref(lm->table);
		g_free(lm);
	}
}

/* Adding items */
static void imquic_listmap_add_to_table(imquic_listmap *lm, void *key, void *item) {
	if(lm != NULL) {
		if(lm->type == IMQUIC_LISTMAP_NUMBER) {
			g_hash_table_insert(lm->table, key, item);
		} else if(lm->type == IMQUIC_LISTMAP_STRING && key != NULL) {
			g_hash_table_insert(lm->table, g_strdup((char *)key), item);
		} else if(lm->type == IMQUIC_LISTMAP_NUMBER64) {
			uint64_t *num = (uint64_t *)key;
			g_hash_table_insert(lm->table, imquic_dup_uint64(*num), item);
		}
	}
}

int imquic_listmap_prepend(imquic_listmap *lm, void *key, void *item) {
	if(lm == NULL || (lm->type == IMQUIC_LISTMAP_STRING && key == NULL))
		return -1;
	/* If the key exists already, get rid of that first */
	if(imquic_listmap_find(lm, key))
		imquic_listmap_remove(lm, key);
	/* Prepend in the list */
	lm->list = g_list_prepend(lm->list, item);
	if(lm->last == NULL)
		lm->last = lm->list;
	lm->index = NULL;
	/* Add to the map */
	imquic_listmap_add_to_table(lm, key, item);
	lm->length++;
	return 0;
}

int imquic_listmap_append(imquic_listmap *lm, void *key, void *item) {
	if(lm == NULL || (lm->type == IMQUIC_LISTMAP_STRING && key == NULL))
		return -1;
	/* If the key exists already, get rid of that first */
	if(imquic_listmap_find(lm, key))
		imquic_listmap_remove(lm, key);
	/* Append to the list */
	lm->last = g_list_append(lm->last, item);
	if(lm->list == NULL)
		lm->list = lm->last;
	if(lm->last->next != NULL)
		lm->last = lm->last->next;
	lm->index = NULL;
	/* Add to the map */
	imquic_listmap_add_to_table(lm, key, item);
	lm->length++;
	return 0;
}

/* Removing items */
int imquic_listmap_remove(imquic_listmap *lm, void *key) {
	if(lm == NULL || (lm->type == IMQUIC_LISTMAP_STRING && key == NULL))
		return -1;
	void *item = g_hash_table_lookup(lm->table, key);
	if(item != NULL) {
		lm->list = g_list_remove(lm->list, item);
		/* FIXME Is there a more efficient way to update the tail? */
		lm->last = g_list_last(lm->list);
		g_hash_table_remove(lm->table, key);
		lm->length--;
	}
	return 0;
}

int imquic_listmap_clear(imquic_listmap *lm) {
	if(lm == NULL)
		return -1;
	g_hash_table_remove_all(lm->table);
	g_list_free(lm->list);
	lm->list = NULL;
	lm->last = NULL;
	lm->index = NULL;
	lm->length = 0;
	return 0;
}

/* Finding items */
void *imquic_listmap_find(imquic_listmap *lm, void *key) {
	if(lm == NULL || (lm->type == IMQUIC_LISTMAP_STRING && key == NULL))
		return NULL;
	return g_hash_table_lookup(lm->table, key);
}

gboolean imquic_listmap_contains(imquic_listmap *lm, void *item) {
	if(lm == NULL || lm->list == NULL)
		return FALSE;
	return g_list_find(lm->list, item) != NULL;
}

/* Traversing the list */
void imquic_listmap_traverse(imquic_listmap *lm) {
	if(lm != NULL)
		lm->index = NULL;
}

void *imquic_listmap_next(imquic_listmap *lm, gboolean *found) {
	if(found)
		*found = FALSE;
	if(lm == NULL)
		return NULL;
	lm->index = lm->index ? lm->index->next : lm->list;
	if(lm->index != NULL) {
		/* Found */
		if(found)
			*found = TRUE;
		return lm->index->data;
	}
	/* We reached the end of the list */
	return NULL;
}

void *imquic_listmap_prev(imquic_listmap *lm, gboolean *found) {
	if(found)
		*found = FALSE;
	if(lm == NULL || lm->index == NULL)
		return NULL;
	lm->index = lm->index->prev;
	if(lm->index != NULL) {
		/* Found */
		if(found)
			*found = TRUE;
		return lm->index->data;
	}
	/* We reached the beginning of the list */
	return NULL;
}
