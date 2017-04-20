#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <errno.h>

#include "rt_names.h"
#include "libnetlink.h"
#include "libgenl.h"
#include "ll_map.h"
#include "if_util.h"

#define	c_err	printf

struct nlmsg_list
{
	struct nlmsg_list *next;
	struct nlmsghdr	  h;
};

struct nlmsg_chain
{
	struct nlmsg_list *head;
	struct nlmsg_list *tail;
};

static int store_nlmsg(const struct sockaddr_nl *who, struct nlmsghdr *n,
		       void *arg)
{
	struct nlmsg_chain *lchain = (struct nlmsg_chain *)arg;
	struct nlmsg_list *h;

	h = malloc(n->nlmsg_len+sizeof(void*));
	if (h == NULL)
		return -1;

	memcpy(&h->h, n, n->nlmsg_len);
	h->next = NULL;

	if (lchain->tail)
		lchain->tail->next = h;
	else
		lchain->head = h;
	lchain->tail = h;

	ll_remember_index(who, n, NULL);
	return 0;
}

static void free_nlmsg_chain(struct nlmsg_chain *info)
{
	struct nlmsg_list *l, *n;

	for (l = info->head; l; l = n) {
		n = l->next;
		free(l);
	}
}

static int store_addrinfo(struct nlmsghdr *n, void *arg)
{
	struct ifs_node *ifn = (struct ifs_node *)arg;
	struct ifs_addr *addr, **pp;
	struct ifaddrmsg *ifa = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr * rta_tb[IFA_MAX+1];

	if (n->nlmsg_type != RTM_NEWADDR)
		return 0;
	len -= NLMSG_LENGTH(sizeof(*ifa));
	if (len < 0) {
		c_err("BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	parse_rtattr(rta_tb, IFA_MAX, IFA_RTA(ifa),
		     n->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));

	if (!rta_tb[IFA_LOCAL])
		rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];
	if (!rta_tb[IFA_ADDRESS])
		rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];

	if (ifa->ifa_family != AF_INET && ifa->ifa_family != AF_INET6)
		return 0;

	addr = malloc(sizeof(struct ifs_addr));
	if (!addr) {
		c_err("Out of memory\n");
		return -1;
	}
	memset(addr, 0, sizeof(struct ifs_addr));

	addr->af = ifa->ifa_family;

	if (rta_tb[IFA_LOCAL]) {
		memcpy(addr->addr, RTA_DATA(rta_tb[IFA_LOCAL]),
			RTA_PAYLOAD(rta_tb[IFA_LOCAL]));

		if (rta_tb[IFA_ADDRESS] == NULL ||
		    memcmp(RTA_DATA(rta_tb[IFA_ADDRESS]), RTA_DATA(rta_tb[IFA_LOCAL]),
			   ifa->ifa_family == AF_INET ? 4 : 16) == 0) {
			addr->prefixlen = ifa->ifa_prefixlen;
		}
	}

	if (rta_tb[IFA_LABEL])
		strcpy(addr->alias, rta_getattr_str(rta_tb[IFA_LABEL]));

	for (pp = &ifn->addrs; (*pp) != NULL; pp = &((*pp)->next))
		;
	*pp = addr;
	ifn->ifs_num++;

	return 0;
}

static int store_selected_addrinfo(int ifindex, struct nlmsg_list *ainfo,
	struct ifs_chain *ifs)
{
	for ( ;ainfo ;  ainfo = ainfo->next) {
		struct nlmsghdr *n = &ainfo->h;
		struct ifaddrmsg *ifa = NLMSG_DATA(n);

		if (n->nlmsg_type != RTM_NEWADDR)
			continue;

		if (n->nlmsg_len < NLMSG_LENGTH(sizeof(ifa)))
			return -1;

		if (ifa->ifa_index != ifindex)
			continue;

		store_addrinfo(n, ifs->tail);
	}
	return 0;
}

static int store_linkinfo(struct nlmsghdr *n, void *arg)
{
	struct ifs_chain *chain = (struct ifs_chain *)arg;
	struct ifs_node *ifn;
	struct ifinfomsg *ifi = NLMSG_DATA(n);
	struct rtattr * tb[IFLA_MAX+1];
	int len = n->nlmsg_len;

	if (n->nlmsg_type != RTM_NEWLINK && n->nlmsg_type != RTM_DELLINK)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		return -1;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (tb[IFLA_IFNAME] == NULL) {
		c_err("BUG: device with ifindex %d has nil ifname\n", ifi->ifi_index);
	}

	if (n->nlmsg_type == RTM_DELLINK) {
		c_err("RTM_DELLINK, exit\n");
		return 0;
	}

	ifn = malloc(sizeof(struct ifs_node));
	if (!ifn) {
		c_err("Out of memory\n");
		return -1;
	}
	memset(ifn, 0, sizeof(struct ifs_node));
	strcpy(ifn->link,
		tb[IFLA_IFNAME] ? rta_getattr_str(tb[IFLA_IFNAME]) : "<nil>");
	if (tb[IFLA_MTU])
		ifn->mtu = *(int*)RTA_DATA(tb[IFLA_MTU]);

	if (chain->tail == NULL)
		chain->head = chain->tail = ifn;
	else {
		chain->tail->next = ifn;
		chain->tail = ifn;
	}
	chain->node_num++;

	return 1;
}

void free_ifs_chain(struct ifs_chain *ifs)
{
	struct ifs_node *np, **npp;
	struct ifs_addr *ap, **app;

	for (npp = &ifs->head; *npp;) {
		np = *npp;
		for (app = &np->addrs; *app;) {
			ap = *app;
			*app = ap->next;
			free(ap);
		}
		*npp = np->next;
		free(np);
	}
}

struct ifs_chain * get_all_ifs(void)
{
	struct rtnl_handle rth = { .fd = -1 };
	struct nlmsg_chain linfo = { NULL, NULL};
	struct nlmsg_chain ainfo = { NULL, NULL};
	struct nlmsg_list *l;
	struct ifs_chain *ifs = NULL;
	int ret = 0;

	if (rtnl_open(&rth, 0) < 0) {
		c_err("rtnl_open() failed\n");
		return NULL;
	}

	if (rtnl_wilddump_request(&rth, AF_UNSPEC, RTM_GETLINK) < 0) {
		c_err("Cannot send dump request: %s, error=%d", strerror(errno), errno);
		goto out2;
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, &linfo) < 0) {
		c_err("Dump terminated\n");
		goto out2;
	}

	if (rtnl_wilddump_request(&rth, AF_UNSPEC, RTM_GETADDR) < 0) {
		c_err("Cannot send dump request: %s, error=%d", strerror(errno), errno);
		goto out1;
	}

	if (rtnl_dump_filter(&rth, store_nlmsg, &ainfo) < 0) {
		c_err("Dump terminated\n");
		goto out1;
	}

	ifs = malloc(sizeof(struct ifs_chain));
	if (!ifs) {
		c_err("Out of memory");
		goto out;
	}
	memset(ifs, 0, sizeof(struct ifs_chain));

	for (l = linfo.head; l; l = l->next) {
		if ((ret = store_linkinfo(&l->h, ifs)) > 0) {
			struct ifinfomsg *ifi = NLMSG_DATA(&l->h);
			store_selected_addrinfo(ifi->ifi_index,
							ainfo.head, ifs);
		}
	}

out:
	free_nlmsg_chain(&ainfo);
out1:
	free_nlmsg_chain(&linfo);
out2:
	rtnl_close(&rth);

	return ifs;
}

void print_ifs_chain(struct ifs_chain *ifs)
{
	struct ifs_node *ifn;
	struct ifs_addr *addr;
	char ipaddr[INET6_ADDRSTRLEN] = "\0";

	for (ifn = ifs->head; ifn != NULL; ifn = ifn->next) {
		fprintf(stderr, "%s mtu %d\n", ifn->link, ifn->mtu);
		for (addr = ifn->addrs; addr != NULL; addr = addr->next) {
			fprintf(stderr, "\t%s ", addr->af == AF_INET ? "inet" : "inet6");
			inet_ntop(addr->af, addr->addr, ipaddr, INET6_ADDRSTRLEN);
			fprintf(stderr, "%s", ipaddr);
			fprintf(stderr, "/%d ", addr->prefixlen);
			fprintf(stderr, "%s\n", addr->alias);
		}
	}
}

#if	0
int main(int argc, char *argv)
{
	struct ifs_chain *ifs;

	ifs = get_all_ifs();
	if (ifs != NULL) {
		print_ifs_chain(ifs);
		free_ifs_chain(ifs);
	}

	return 0;
}
#endif
