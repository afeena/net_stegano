/*
 * File:   main.c
 * Author: mainn_000
 *
 * Created on October 19, 2014, 9:54 PM
 */

#include <linux/kernel.h>
#include <linux/module.h>
//

#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_AUTHOR("afeena & mainnika");
MODULE_DESCRIPTION("tratalolo");
MODULE_LICENSE("GPL");

struct nf_hook_ops bundle;

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
	__u32 data_len;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);

	if (!iph || !tcph || !tcph->psh)
		return NF_ACCEPT;

	steg_msg = kstrdup("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", GFP_KERNEL);
	data_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
	data = (char *)((unsigned char *)tcph + (tcph->doff << 2));

	memcpy(data, steg_msg, data_len);

	kfree(steg_msg);

	printk(KERN_ALERT "STEG>> sending stegano data \"%.*s\" with csum %u\n", data_len, data, htons(tcph->check));



//	printk(KERN_ALERT "STEG>> data_len: %u\n", data_len);
//	printk(KERN_ALERT "STEG>> hello\n");

//	struct sk_buff *skb_data;

//	if (!skb->tail)
//		return NF_ACCEPT;



//	skb_data = tcp_write_queue_tail(skb->);
//	steg_msg = kstrdup("deadbeefdeadbeefdeadbeefdeadbeefdeadbeef", GFP_KERNEL);

//	skb_data->data = kmalloc(skb_data->len, GFP_KERNEL);
//	memcpy(skb_data->data, steg_msg, skb_data->len);

//	kfree(steg_msg);

//	printk(KERN_ALERT "STEG>> hdr_len, len : %u, %u", skb->hdr_len, skb->len);
//	printk(KERN_DEBUG "STEG>> sending data \"%.*s\"\n", skb->len, skb->data);

	return NF_ACCEPT;
}

int on_init(void){

	printk(KERN_DEBUG "HELLO, ITS ME, TRATALOLO");

	bundle.hook = on_hook;
	bundle.owner = THIS_MODULE;
	bundle.pf = PF_INET;
	bundle.hooknum = NF_INET_POST_ROUTING;
	bundle.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&bundle);

	return 0;
}

void on_exit(void){

	printk(KERN_DEBUG "BYE BYE, TRATALOLO");

	nf_unregister_hook(&bundle);

	return;
}

module_init(on_init);
module_exit(on_exit);



