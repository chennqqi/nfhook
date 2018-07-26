#ifndef NFHOOK_H
#define NFHOOK_H

struct sk_buff;
struct net_device;
struct net;

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

extern NET_NOTIFYFN_T nfhook_pernet_init_callback;
extern NET_NOTIFYFN_T nfhook_pernet_exit_callback;
#endif

extern PACKET_HANDLER nfhook_packet_handler;


#endif // NFHOOK_H
