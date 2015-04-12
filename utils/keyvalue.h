#include <linux/kernel.h>
#include <linux/module.h>

MODULE_AUTHOR("afeena & mainnika");
MODULE_DESCRIPTION("tratalolo");
MODULE_LICENSE("GPL");

typedef uint32_t keytype;
typedef void* valuetype;

typedef struct keyvalue_t keyvalue_t;
typedef struct storage_t storage_t;

struct keyvalue_t
{
	keytype key;
	valuetype value;
	keyvalue_t* next;
	keyvalue_t* prev;
};

struct storage_t
{
	keyvalue_t** head;
	keyvalue_t** tail;

	uint32_t size;
};

storage_t* keyvalue_create(void);
keyvalue_t* keyvalue_push(storage_t* storage, keytype key, valuetype value);
keyvalue_t* keyvalue_search(storage_t* storage, keytype key);
keyvalue_t* keyvalue_erase(storage_t* storage, keytype key);