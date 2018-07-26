#ifndef NFHOOK_COMPAT_H
#define NFHOOK_COMPAT_H

#include <linux/version.h>
#include <linux/netfilter.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <uapi/linux/netfilter_arp.h>

#include "nfhook.h"
#if 0
// ------------------------------------------------------------------------
// kernel API compatibility

typedef	int (*PACKET_HANDLER)(int pf, unsigned int hooknum,
        struct sk_buff *skb, const struct net_device *in,
        const struct net_device *out);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,3,0)
#define SUPPORT_NF_REGISTER_NET_HOOK 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#define SUPPORT_PERNET_NOTIFIACTION
typedef	int (*NET_NOTIFYFN_T)(struct net *);
#endif
#endif

// ------------------------------------------------------------------------
// hooking compatibility

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
typedef	int (*HOOK_OKFN_T)(struct net *, struct sock *, struct sk_buff *);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
typedef	int (*HOOK_OKFN_T)(struct sock *, struct sk_buff *);
#define	HOOK_OKFN_ARGS(sk,skb)	sk,skb
#else
typedef	int (*HOOK_OKFN_T)(struct sk_buff *);
#define	HOOK_OKFN_ARGS(sk,skb)	skb
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)

#define HOOK_SKB_ARG			struct sk_buff *the_hook_skb_arg
#define DECLARE_HOOK_SKB_VAR(skb)	struct sk_buff *skb = (the_hook_skb_arg)
#define SKB_TO_HOOK_ARG(skb)            (skb)
#define HOOK_SKB_REPLACE(oskb, nskb, sk, okfn, rc) ({ \
	kfree_skb(oskb); \
	(okfn)(HOOK_OKFN_ARGS(sk, nskb)); \
	rc = NF_STOLEN; \
})

#else // 2.6.24

#define HOOK_SKB_ARG			struct sk_buff **the_hook_skb_arg
#define DECLARE_HOOK_SKB_VAR(skb)	struct sk_buff *skb = *(the_hook_skb_arg)
#define SKB_TO_HOOK_ARG(skb)            &(skb)
#define HOOK_SKB_REPLACE(oskb, nskb, sk, okfn, rc) ({ \
	BUG_ON((*the_hook_skb_arg) != (oskb)); \
	kfree_skb(oskb); \
	*the_hook_skb_arg = nskb; \
	rc = NF_ACCEPT; \
})

#endif


// ------------------------------------------------------------------------
// define pf for versions

#ifdef NFPROTO_IPV4
	#define HOOK_PF_IPV4	NFPROTO_IPV4
	#define HOOK_PF_IPV6	NFPROTO_IPV6
	#define HOOK_PF_ARP	NFPROTO_ARP
#else
	#define HOOK_PF_IPV4	PF_INET
	#define HOOK_PF_IPV6	PF_INET6
	#define HOOK_PF_ARP	NF_ARP
#endif

// ------------------------------------------------------------------------
// define hook points for versions

#ifdef NF_IP_PRE_ROUTING
	#define HOOK_NF_PRE_ROUTING	NF_IP_PRE_ROUTING
	#define HOOK_NF_POST_ROUTING	NF_IP_POST_ROUTING
	#define HOOK_NF_LOCAL_IN	NF_IP_LOCAL_IN
	#define HOOK_NF_LOCAL_OUT	NF_IP_LOCAL_OUT
#else
	#define HOOK_NF_PRE_ROUTING	NF_INET_PRE_ROUTING
	#define HOOK_NF_POST_ROUTING	NF_INET_POST_ROUTING
	#define HOOK_NF_LOCAL_IN	NF_INET_LOCAL_IN
	#define HOOK_NF_LOCAL_OUT	NF_INET_LOCAL_OUT
#endif

#endif // NFHOOK_COMPAT_H
