#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "../utils/keyvalue.h"

MODULE_AUTHOR("afeena & mainnika");
MODULE_DESCRIPTION("tratalolo");
MODULE_LICENSE("GPL");

storage_t* storage;
struct nf_hook_ops bundle;
uint32_t stegano_ratio;

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
	tcph->check = tcp_v4_check(skb->len - (iph->ihl << 2),
				iph->saddr, iph->daddr,
				csum_partial((char *) tcph, skb->len - (iph->ihl << 2), 0));

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

	data_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
	data = (char *) ((unsigned char *) tcph + (tcph->doff << 2));

	value = keyvalue_erase(storage, ntohl(tcph->seq));

	if (value != NULL)
		goto flip;

	if (stegano_chance(skb) && (data_len <= 40) && (data_len >= 4))
		goto replace;

	goto out;

replace:

	keyvalue_push(storage, ntohl(tcph->seq), (void*)kstrndup(data, data_len, GFP_KERNEL));

	steg_msg = kstrdup("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", GFP_KERNEL);
	memcpy(data, steg_msg, data_len);
	kfree(steg_msg);

	tcph->check = htons(0xFFFF);
	skb->ip_summed = CHECKSUM_COMPLETE;

	printk(KERN_ALERT "STEG>> sending stegano data \"%.*s\" csum %u\n", data_len, data, tcph->check);

	goto out;

flip:

	memcpy((void*)data, value->value, data_len);

	tcph->check = csum_calc(skb, tcph, iph);
	skb->ip_summed = CHECKSUM_COMPLETE;

	kfree(value->value);
	kfree(value);

	printk(KERN_ALERT "STEG>> restore original data \"%.*s\" csum %u\n", data_len, data, tcph->check);

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



