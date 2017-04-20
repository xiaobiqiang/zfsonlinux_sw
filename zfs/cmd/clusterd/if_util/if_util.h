#ifndef	_IF_UTIL_H
#define	_IF_UTIL_H

#include <net/if.h>

#ifndef	INET6_ADDRSTRLEN
#define	INET6_ADDRSTRLEN	(48)
#endif

#ifndef	IFALIASZ
#define	IFALIASZ	256
#endif

struct ifs_addr
{
	struct ifs_addr	*next;
	int	af;
	int	prefixlen;
	char	addr[INET6_ADDRSTRLEN];
	char	alias[IFALIASZ];
};

struct ifs_node
{
	struct ifs_node	*next;
	char	link[IFNAMSIZ];
	int	mtu;
	int	ifs_num;
	struct ifs_addr	*addrs;
};

struct ifs_chain
{
	struct ifs_node *head;
	struct ifs_node	*tail;
	int	node_num;
};

struct ifs_chain * get_all_ifs(void);
void free_ifs_chain(struct ifs_chain *ifs);

#endif	/* _IF_UTIL_H */
