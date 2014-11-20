/*
 * File:   main.c
 * Author: mainn_000
 *
 * Created on October 19, 2014, 9:54 PM
 */

#include <linux/kernel.h>
#include <linux/module.h>
//
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

	return NF_ACCEPT;
}

int on_init(void){

	printk(KERN_DEBUG "HELLO, ITS ME, TRATALOLO");

	bundle.hook = on_hook;
	bundle.owner = THIS_MODULE;
	bundle.pf = PF_INET;
	bundle.hooknum = NF_INET_PRE_ROUTING;
	bundle.priority = NF_IP_PRI_FIRST;

	nf_register_hook(&bundle);

	return 0;
}

void on_exit(void){

	nf_unregister_hook(&bundle);

	return;
}

module_init(on_init);
module_exit(on_exit);



