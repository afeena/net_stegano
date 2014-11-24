#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_AUTHOR("afeena & mainnika");
MODULE_DESCRIPTION("tratalolo");
MODULE_LICENSE("GPL");

typedef unsigned int keytype;
typedef unsigned char* valuetype;

typedef struct keyvalue_t keyvalue_t;
typedef struct storage_t storage_t;
struct nf_hook_ops bundle;
uint32_t stegano_ratio;

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

storage_t* storage = NULL;

storage_t* keyvalue_create(void)
{
	storage_t* storage;

	storage = kmalloc(sizeof (storage_t), GFP_KERNEL);

	storage->head = kmalloc(sizeof (keyvalue_t), GFP_KERNEL);
	storage->tail = kmalloc(sizeof (keyvalue_t), GFP_KERNEL);
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

bool stegano_chance(struct sk_buff *skb)
{
	bool steg_xmit = false;
	unsigned int ran_num = get_random_int();

	if (ran_num < (UINT_MAX / 100) * stegano_ratio)
		steg_xmit = true;

	return steg_xmit;
}

__sum16 csum_calc(struct sk_buff *skb,
		  struct tcphdr *tcph,
		  struct iphdr *iph)
{
	__sum16 old;

	old = tcph->check;
	tcph->check = 0;
	tcph->check = tcp_v4_check(skb->len - 4 * iph->ihl,
				iph->saddr, iph->daddr,
				csum_partial((char *) tcph, skb->len - 4 * iph->ihl, 0));
	swap(old, tcph->check);
	return old;
}

unsigned int on_hook(const struct nf_hook_ops *ops,
		     struct sk_buff *skb,
		     const struct net_device *in,
		     const struct net_device *out,
		     int (*okfn)(struct sk_buff *))
{
	struct tcphdr * tcph;
	struct iphdr * iph;
	unsigned char * data;
	unsigned char * steg_msg;
	uint32_t data_len;
	keyvalue_t* value;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);

	if (!iph || !tcph || !tcph->psh)
		return NF_ACCEPT;

	value = keyvalue_erase(storage, ntohl(tcph->seq));
	data_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
	data = (char *) ((unsigned char *) tcph + (tcph->doff << 2));

	if (value != NULL)
		goto flip;

	if (stegano_chance(skb))
		goto stegano;

	goto out;

stegano:

	keyvalue_push(storage, ntohl(tcph->seq), kstrndup(data, data_len, GFP_KERNEL));

	steg_msg = kstrdup("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", GFP_KERNEL);
	memcpy(data, steg_msg, data_len);
	kfree(steg_msg);
	tcph->check ^= tcph->seq;
	printk(KERN_ALERT "STEG>> sending stegano data \"%.*s\"\n", data_len, data);

	goto out;

flip:

	memcpy(data, value->value, data_len);
	tcph->check = csum_calc(skb, tcph, iph);

	kfree(value->value);
	kfree(value);

	printk(KERN_ALERT "STEG>> restore original data \"%.*s\"\n", data_len, data);

out:

	return NF_ACCEPT;
}

int on_init(void)
{
	printk(KERN_DEBUG "HELLO, ITS ME, TRATALOLO");

	bundle.hook = on_hook;
	bundle.owner = THIS_MODULE;
	bundle.pf = PF_INET;
	bundle.hooknum = NF_INET_LOCAL_OUT;
	bundle.priority = NF_IP_PRI_FIRST;

	storage = keyvalue_create();

	stegano_ratio = 20;

	nf_register_hook(&bundle);

	return 0;
}

void on_exit(void)
{
	printk(KERN_DEBUG "BYE BYE, TRATALOLO");

	nf_unregister_hook(&bundle);

	return;
}

module_init(on_init);
module_exit(on_exit);



