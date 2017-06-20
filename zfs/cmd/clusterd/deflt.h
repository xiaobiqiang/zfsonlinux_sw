#ifndef	_DEFLT_H
#define	_DEFLT_H

#ifdef	__cplusplus
extern "C" {
#endif

#define	DEFLT	"/etc/default"

#ifdef __STDC__
extern int defopen(char *);
extern char *defread(char *);
#else
extern int defopen();
extern char *defread();
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _DEFLT_H */
