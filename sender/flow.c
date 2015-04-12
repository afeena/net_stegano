#include "flow.h"
#include <linux/slab.h>

flow_t* flow_select(storage_t* storage, __be32 daddr)
{
	keyvalue_t* finded;
	flow_t* flow;

	finded = keyvalue_search(storage, daddr);

	if (finded == NULL)
	{
		flow = (flow_t*) kmalloc(sizeof (flow_t), GFP_KERNEL);
		finded = keyvalue_push(storage, daddr, (void*) flow);

		flow->head = NULL;
		flow->tail = NULL;
		flow->count = 0;

		return flow;
	}

	return (flow_t*) finded->value;
}

size_t flow_push(flow_t* flow, void* data, size_t len)
{
	msg_t* msg;

	msg = (msg_t*) kmalloc(sizeof (msg_t), GFP_KERNEL);
	msg->data = data;
	msg->total_len = len;
	msg->offset = 0;
	msg->next = NULL;

	if (flow->head == NULL)
	{
		flow->head = msg;
		flow->tail = msg;
		flow->count = 1;
		return 1;
	}

	flow->tail->next = msg;
	flow->count++;
	return flow->count;
}

void* flow_pop(flow_t* flow, size_t pop_bytes, size_t* writed_bytes)
{
	void* data;
	msg_t* head;

	head = flow->head;

	if (head == NULL)
		return NULL;

	*writed_bytes = min(pop_bytes, head->total_len - head->offset);

	data = kmalloc(*writed_bytes, GFP_KERNEL);
	memcpy(data, head->data + head->offset, *writed_bytes);

	head->offset += *writed_bytes;

	if (head->offset >= head->total_len)
	{
		flow->head = head->next;

		if (flow->head == NULL)
			flow->tail = NULL;

		flow->count--;

		kfree(head->data);
		kfree(head);
	}

	return data;
}