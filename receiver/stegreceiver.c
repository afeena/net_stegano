#include <linux/kernel.h>
#include <linux/module.h>

#include <net/tcp.h>
#include <linux/ip.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

MODULE_AUTHOR("afeena & mainnika");
MODULE_DESCRIPTION("tratalolo");
MODULE_LICENSE("GPL");

struct nf_hook_ops bundle;

__sum16 csum_calc(struct sk_buff *skb,
		  struct tcphdr *tcph,
		  struct iphdr *iph)
{
	__sum16 old;

	old = tcph->check;
	tcph->check = 0;
	tcph->check = tcp_v4_check(skb->len - (iph->ihl << 2),
				iph->saddr, iph->daddr,
				csum_partial(tcph, skb->len - (iph->ihl << 2), 0));

	swap(old, tcph->check);

	return old;
}

bool csum_valid(struct sk_buff *skb,
		struct tcphdr *tcph,
		struct iphdr *iph)
{
	return tcph->check == csum_calc(skb, tcph, iph);
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
	__u32 data_len;
	__sum16 check;

	if (!skb)
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	tcph = tcp_hdr(skb);
	check = csum_calc(skb, tcph, iph);

	if (!iph || !tcph || !tcph->psh || skb->ip_summed > 0)
		return NF_ACCEPT;

	data_len = ntohs(iph->tot_len) - (iph->ihl << 2) - (tcph->doff << 2);
	data = (char *) ((unsigned char *) tcph + (tcph->doff << 2));

	printk(KERN_ALERT "STEG>> receive stegano data \"%.*s\" received: %u (calculated: %u)\n", data_len, data, tcph->check, check);

	return NF_ACCEPT;
}

int on_init(void)
{
	printk(KERN_DEBUG "HELLO, ITS ME, TRATALOLO");

	bundle.hook = on_hook;
	bundle.owner = THIS_MODULE;
	bundle.pf = PF_INET;
	bundle.hooknum = NF_INET_LOCAL_IN;
	bundle.priority = NF_IP_PRI_FIRST;

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



