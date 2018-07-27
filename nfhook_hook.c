#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Johnnie Deacon");
MODULE_DESCRIPTION("A universal netfilter hook frontend.");
MODULE_VERSION("0.1"); 

#include "compat.h"

static DEFINE_SPINLOCK(handler_lock);
static PACKET_HANDLER packet_handler = NULL;

static unsigned int
nf_callback_all(int pf, unsigned int hooknum,
        HOOK_SKB_ARG, const struct net_device *in,
        const struct net_device *out, struct sock *sk, HOOK_OKFN_T okfn)
{
	DECLARE_HOOK_SKB_VAR(skb);

	if (packet_handler) {
		int rc = packet_handler(pf, hooknum, skb, in, out);
		return rc;
	}

	return NF_ACCEPT;
}

// ------------------------------------------------------------------------
// these are the hook functions we registered with the kernel, they pass down
// the PF_ constant and aggregate down to nf_packet_wrapper_all() below
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
static unsigned int
nf_callback_inet(void *priv, HOOK_SKB_ARG, const struct nf_hook_state *state)
{
	return nf_callback_all(HOOK_PF_IPV4,
			state->hook, the_hook_skb_arg, state->in, state->out, state->sk, state->okfn);
}

static unsigned int
nf_callback_inet6(void *priv, HOOK_SKB_ARG, const struct nf_hook_state *state)
{
	return nf_callback_all(HOOK_PF_IPV6,
			state->hook, the_hook_skb_arg, state->in, state->out, state->sk, state->okfn);
}

static unsigned int
nf_callback_arp(void *priv, HOOK_SKB_ARG, const struct nf_hook_state *state)
{
	return nf_callback_all(HOOK_PF_ARP,
			state->hook, the_hook_skb_arg, state->in, state->out, state->sk, state->okfn);
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
static unsigned int
nf_callback_inet(const struct nf_hook_ops *ops, HOOK_SKB_ARG, const struct nf_hook_state *state)

{
	return nf_callback_all(HOOK_PF_IPV4,
			state->hook, the_hook_skb_arg, state->in, state->out, state->sk, state->okfn);
}

static unsigned int
nf_callback_inet6(const struct nf_hook_ops *ops, HOOK_SKB_ARG, const struct nf_hook_state *state)
{
	return nf_callback_all(HOOK_PF_IPV6,
			state->hook, the_hook_skb_arg, state->in, state->out, state->sk, state->okfn);
}

static unsigned int
nf_callback_arp(const struct nf_hook_ops *ops, HOOK_SKB_ARG, const struct nf_hook_state *state)
{
	nf_callback_all(HOOK_PF_ARP,
			state->hook, the_hook_skb_arg, state->in, state->out, state->sk, state->okfn);
	return NF_ACCEPT;
}
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0) || defined(TB_LINUX_KERNEL_API_NFHOOKS_FN_RHEL7)
static unsigned int
nf_callback_inet(const struct nf_hook_ops *ops, HOOK_SKB_ARG, const struct net_device *in,
	const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	return nf_callback_all(HOOK_PF_IPV4,
			ops->hooknum, the_hook_skb_arg, in, out, NULL, okfn);
}

static unsigned int
nf_callback_inet6(const struct nf_hook_ops *ops, HOOK_SKB_ARG, const struct net_device *in,
	const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	return nf_callback_all(HOOK_PF_IPV6,
			ops->hooknum, the_hook_skb_arg, in, out, NULL, okfn);
}

static unsigned int
nf_callback_arp(const struct nf_hook_ops *ops, HOOK_SKB_ARG, const struct net_device *in,
	const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	nf_callback_all(HOOK_PF_ARP,
			ops->hooknum, the_hook_skb_arg, in, out, NULL, okfn);
	return NF_ACCEPT;
}
#else
static unsigned int
nf_callback_inet(unsigned int hooknum, HOOK_SKB_ARG, const struct net_device *in,
	const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	return nf_callback_all(HOOK_PF_IPV4,
			hooknum, the_hook_skb_arg, in, out, NULL, okfn);
}

static unsigned int
nf_callback_inet6(unsigned int hooknum, HOOK_SKB_ARG, const struct net_device *in,
	const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	return nf_callback_all(HOOK_PF_IPV6,
			hooknum, the_hook_skb_arg, in, out, NULL, okfn);
}

static unsigned int
nf_callback_arp(unsigned int hooknum, HOOK_SKB_ARG, const struct net_device *in,
	const struct net_device *out, int (*okfn)(struct sk_buff *))
{
	nf_callback_all(HOOK_PF_ARP,
			hooknum, the_hook_skb_arg, in, out, NULL, okfn);
	return NF_ACCEPT;
}
#endif


/**
 * This is the table of hooks we register with netfilter.
 *
 */
#define HOOK_ENTRY(HOOK, PF, HOOKNUM, PRIORITY) \
	{						\
		.enabled = 1,				\
		.hook = {				\
			.hook		= HOOK,		\
			.pf		= PF,		\
			.hooknum	= HOOKNUM,	\
			.priority	= PRIORITY,	\
		},					\
	}

static struct hook_info {
	int enabled;
	struct nf_hook_ops hook;
} hooks[] = {

	// hook points closest to the socket
	HOOK_ENTRY(nf_callback_inet, HOOK_PF_IPV4, HOOK_NF_LOCAL_IN, NF_IP_PRI_LAST),
	HOOK_ENTRY(nf_callback_inet, HOOK_PF_IPV4, HOOK_NF_LOCAL_OUT, NF_IP_PRI_FIRST),
	HOOK_ENTRY(nf_callback_inet6, HOOK_PF_IPV6, HOOK_NF_LOCAL_IN, NF_IP_PRI_LAST),
	HOOK_ENTRY(nf_callback_inet6, HOOK_PF_IPV6, HOOK_NF_LOCAL_OUT, NF_IP_PRI_FIRST),

	// hook points closest to the interfaces
	HOOK_ENTRY(nf_callback_inet, HOOK_PF_IPV4, HOOK_NF_PRE_ROUTING, NF_IP_PRI_FIRST),
	HOOK_ENTRY(nf_callback_inet, HOOK_PF_IPV4, HOOK_NF_POST_ROUTING, NF_IP_PRI_LAST),
	HOOK_ENTRY(nf_callback_inet6, HOOK_PF_IPV6, HOOK_NF_PRE_ROUTING, NF_IP_PRI_FIRST),
	HOOK_ENTRY(nf_callback_inet6, HOOK_PF_IPV6, HOOK_NF_POST_ROUTING, NF_IP_PRI_LAST),

	HOOK_ENTRY(nf_callback_arp, HOOK_PF_ARP, NF_ARP_IN, NF_IP_PRI_FIRST),
	HOOK_ENTRY(nf_callback_arp, HOOK_PF_ARP, NF_ARP_OUT, NF_IP_PRI_LAST),

};

#define HOOKS_COUNT (sizeof(hooks)/sizeof(hooks[0]))

#ifdef SUPPORT_NF_REGISTER_NET_HOOK
static int _hook_action_pernet(struct net *net)
{
	int i, ret;

	printk("Doing %s\n", __FUNCTION__);
	for (i = 0; i < HOOKS_COUNT; i++) {
		ret = nf_register_net_hook(net, &hooks[i].hook);
		if (ret < 0)
			goto register_error;
	}

	return 0;

register_error:
	for (--i; i >= 0; i--) {
		nf_register_net_hook(net, &hooks[i].hook);
	}
	return -1;
}

static int _unhook_action_pernet(struct net *net)
{
	int i;

	printk("Doing %s\n", __FUNCTION__);
	for (i = 0; i < HOOKS_COUNT; i++) {
		nf_unregister_net_hook(net, &hooks[i].hook);
	}

	return 0;
}

#else
static int _hook_action_pernet(struct net *net) { return 0; }
static int _unhook_action_pernet(struct net *net) { return 0; }

static int _hook_action(void)
{
	int i, ret;

	printk("Doing %s\n", __FUNCTION__);
	for (i = 0; i < HOOKS_COUNT; i++) {
		ret = nf_register_hook(&hooks[i].hook);
		if (ret < 0)
			goto register_error;
	}

	return 0;

register_error:
	for (--i; i >= 0; i--) {
		nf_unregister_hook(&hooks[i].hook);
	}
	return -1;
}

static int _unhook_action(void)
{
	int i;

	printk("Doing %s\n", __FUNCTION__);
	for (i = 0; i < HOOKS_COUNT; i++) {
		nf_unregister_hook(&hooks[i].hook);
	}

	return 0;
}

#endif


#ifdef SUPPORT_PERNET_NOTIFIACTION

NET_NOTIFYFN_T nfhook_pernet_init_callback = NULL;
NET_NOTIFYFN_T nfhook_pernet_exit_callback = NULL;

static int pernet_init(struct net *net)
{
	_hook_action_pernet(net);

	if (nfhook_pernet_init_callback)
		nfhook_pernet_init_callback(net);

	return 0;
}

static void pernet_exit(struct net *net)
{
	_unhook_action_pernet(net);

	if (nfhook_pernet_exit_callback)
		nfhook_pernet_exit_callback(net);
}

static struct pernet_operations pernet_ops = {
	.init = pernet_init,
	.exit = pernet_exit,
};
#endif // SUPPORT_PERNET_NOTIFIACTION

int nfhook_enable(PACKET_HANDLER handler)
{
	int ret = 0;

	if (handler == NULL)
		return -ENOENT;

	spin_lock(&handler_lock);

	if (packet_handler) {
		spin_unlock(&handler_lock);
		return -EBUSY;
	}

#ifdef SUPPORT_PERNET_NOTIFIACTION
	ret = register_pernet_subsys(&pernet_ops);
	if (ret < 0) {
		spin_unlock(&handler_lock);
		return ret;
	}
#endif
#ifndef SUPPORT_NF_REGISTER_NET_HOOK
	ret = _hook_action();
	if (ret < 0) {
		spin_unlock(&handler_lock);
		return ret;
	}
#endif

	packet_handler = handler;

	spin_unlock(&handler_lock);
	return 0;
}

int nfhook_disable(void)
{
	spin_lock(&handler_lock);

	if (!packet_handler) {
		spin_unlock(&handler_lock);
		return -ENOENT;
	}

#ifdef SUPPORT_PERNET_NOTIFIACTION
	unregister_pernet_subsys(&pernet_ops);
#endif
#ifndef SUPPORT_NF_REGISTER_NET_HOOK
	_unhook_action();
#endif

	packet_handler = NULL;
	spin_unlock(&handler_lock);
	return 0;
}

static int __init nfhook_init(void)
{
	return 0;
}

static void __exit nfhook_exit(void)
{
}

module_init(nfhook_init);
module_exit(nfhook_exit);

EXPORT_SYMBOL(nfhook_enable);
EXPORT_SYMBOL(nfhook_disable);
#ifdef SUPPORT_PERNET_NOTIFIACTION
EXPORT_SYMBOL(nfhook_pernet_init_callback);
EXPORT_SYMBOL(nfhook_pernet_exit_callback);
#endif
