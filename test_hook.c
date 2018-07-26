//#include <linux/config.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Johnnie Deacon");
MODULE_DESCRIPTION("first testing module.");
MODULE_VERSION("0.1"); 

#include "nfhook.h"

int my_handler(int pf, unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
	const struct net_device *dev = in ?: out;
	if (dev) {
		if (dev_net(dev) == &init_net) printk("%p H %d %d !\n", skb,  pf, hooknum);
		else printk("%p C %d %d !\n", skb, pf, hooknum);
	}
	return NF_ACCEPT;
}

static int __init mod_init(void)
{
	printk("Doing %s\n", __FUNCTION__);

	if (nfhook_packet_handler == NULL) {
		nfhook_packet_handler = my_handler;
	} else {
		printk("Someone has registered hooked! exit.\n");
		return -1;
	}

	printk("Done %s\n", __FUNCTION__);
	return 0;
}

static void __exit mod_exit(void)
{
	printk("Doing %s\n", __FUNCTION__);
	nfhook_packet_handler = NULL;
	printk("Done %s\n", __FUNCTION__);
}

module_init(mod_init);
module_exit(mod_exit);
