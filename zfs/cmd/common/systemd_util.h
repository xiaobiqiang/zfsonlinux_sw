#ifndef	_SYSTEMD_UTIL_H
#define	_SYSTEMD_UTIL_H

extern void systemd_daemonize(char *pid_file);
extern void write_pid(char *pid_file);

#endif /* _SYSTEMD_UTIL_H */
