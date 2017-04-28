#ifndef	_IF_UTIL_H
#define	_IF_UTIL_H

#include <linux/if.h>

#ifndef	INET6_ADDRSTRLEN
#define	INET6_ADDRSTRLEN	(48)
#endif

#ifndef	IFALIASZ
#define	IFALIASZ	256
#endif

enum ifs_link_state {
	ils_unknown = 0,
	ils_notpresent,
	ils_down,
	ils_lowerlayerdown,
	ils_testing,
	ils_dormant,
	ils_up
};

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
	unsigned	flags;
	unsigned	state;
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

typedef void (*link_change_callback)(const char *, unsigned, unsigned);

int add_monitor_ifs(const char *linkname);
int remove_monitor_ifs(const char *linkname);
void init_monitor_ifs(link_change_callback func);

#endif	/* _IF_UTIL_H */
