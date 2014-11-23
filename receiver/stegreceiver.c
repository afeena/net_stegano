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
	__u32 data_len;

	if (!skb || skb->csum_valid)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);

	if (!iph || !tcph || !tcph->psh)
		return NF_ACCEPT;

	data_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
	data = (char *)((unsigned char *)tcph + (tcph->doff << 2));

	printk(KERN_ALERT "STEG>> receive stegano data \"%.*s\"\n", data_len, data);

	return NF_ACCEPT;
}

int on_init(void){

	printk(KERN_DEBUG "HELLO, ITS ME, TRATALOLO");

	bundle.hook = on_hook;
	bundle.owner = THIS_MODULE;
	bundle.pf = PF_INET;
	bundle.hooknum = NF_INET_LOCAL_IN;
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



