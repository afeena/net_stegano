#include "keyvalue.h"

#include <linux/gfp.h>
#include <linux/slab.h>

storage_t* keyvalue_create(void)
{
	storage_t* storage;

	storage = kmalloc(sizeof (storage_t), GFP_KERNEL);

	storage->head = kmalloc(sizeof (keyvalue_t*), GFP_KERNEL);
	storage->tail = kmalloc(sizeof (keyvalue_t*), GFP_KERNEL);
	storage->size = 0;

	(*storage->head) = NULL;
	(*storage->tail) = NULL;

	return storage;
}

keyvalue_t* keyvalue_push(storage_t* storage, keytype key, valuetype value)
{
	keyvalue_t *element;

	element = kmalloc(sizeof (keyvalue_t), GFP_KERNEL);

	element->key = key;
	element->value = value;
	element->prev = (*storage->tail);
	element->next = NULL;

	if ((*storage->head) == NULL)
	{
		(*storage->head) = element;
		(*storage->tail) = element;
	}
	else
	{
		(*storage->tail)->next = element;
		(*storage->tail) = element;
	}

	storage->size++;

	return element;
}

keyvalue_t* keyvalue_search(storage_t* storage, keytype key)
{
	keyvalue_t* element;
	keyvalue_t* next;

	element = NULL;
	next = (*storage->head);

	while (next != NULL)
	{
		if (next->key == key)
		{
			element = next;
			break;
		}

		next = next->next;
	}

	return element;
}

keyvalue_t* keyvalue_erase(storage_t* storage, keytype key)
{
	keyvalue_t* element;

	element = keyvalue_search(storage, key);

	if (element == NULL)
		return NULL;

	if (element->prev != NULL)
		element->prev->next = element->next;
	else
		(*storage->head) = element->next;

	if (element->next != NULL)
		element->next->prev = element->prev;
	else
		(*storage->tail) = element->prev;

	storage->size--;

	element->prev = NULL;
	element->next = NULL;

	return element;
}
