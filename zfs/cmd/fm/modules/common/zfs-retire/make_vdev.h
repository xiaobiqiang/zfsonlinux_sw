#ifndef _MAKE_VDEV_H
#define	_MAKE_VDEV_H

#include <libnvpair.h>
#include <libzfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Virtual device functions
 */

nvlist_t *make_vdev(zpool_handle_t *zhp, int check_rep,
    boolean_t replacing, boolean_t dryrun, int argc, char **argv);
#ifdef	__cplusplus
}
#endif

#endif	/* MAKE_VDEV_H */

