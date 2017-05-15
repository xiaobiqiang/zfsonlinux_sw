#ifndef	__ZFS_MIRROR_DEBUG_H__
#define	__ZFS_MIRROR_DEBUG_H__

#if 0

#define	ENTRY	do {printk("%s ENTER %d\n", __func__, __LINE__);} while (0)
#define	EXIT	do {printk("%s EXIT %d\n", __func__, __LINE__);} while (0)
#define	POSITION(x)	do {printk("%s %d: %s\n", __func__, __LINE__, x);} while (0)
#define	TPOSITION(x)	do {printk("%s %d: :%p, %s\n", __func__, __LINE__, curthread, (x));} while (0)

#else

#define	ENTRY
#define	EXIT
#define	POSITION(x)
#define	TPOSITION(x)

#endif

#endif
