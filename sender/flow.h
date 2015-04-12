#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>

#include "../utils/keyvalue.h"

struct msg_t
{
	void* data;
	size_t total_len;
	size_t offset;

	msg_t* next;
};

struct flow_t
{
	msg_t* head;
	msg_t* tail;

	size_t count;
};

flow_t* flow_select(storage_t* storage, __be32 daddr);

size_t flow_push(flow_t* flow, void* data, size_t len);
void* flow_pop(flow_t* flow, size_t len);

bool flow_destroy(flow_t* flow);