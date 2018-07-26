//#include <linux/config.h>
#include <linux/module.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/netdevice.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Johnnie Deacon");
MODULE_DESCRIPTION("first testing module.");
MODULE_VERSION("0.1"); 

#include "nfhook.h"

int my_handler(int pf, unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out)
{
	const struct net_device *dev = in ?: out;
	if (dev) {
#ifdef SUPPORT_PERNET_NOTIFIACTION
		if (dev_net(dev) == &init_net) printk("%p H %d %d !\n", skb,  pf, hooknum);
		else printk("%p C %d %d !\n", skb, pf, hooknum);
#else
		printk("%p %d %d !\n", skb,  pf, hooknum);
#endif
	}
	return NF_ACCEPT;
}

static int __init mod_init(void)
{
	int ret;

	printk("Doing %s\n", __FUNCTION__);

	ret = nfhook_enable(my_handler);

	printk("Done %s %d\n", __FUNCTION__, ret);
	return ret;
}

static void __exit mod_exit(void)
{
	int ret;

	printk("Doing %s\n", __FUNCTION__);
	ret = nfhook_disable();
	printk("Done %s %d\n", __FUNCTION__, ret);
}

module_init(mod_init);
module_exit(mod_exit);
