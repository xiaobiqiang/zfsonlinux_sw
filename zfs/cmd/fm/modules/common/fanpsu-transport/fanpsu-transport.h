#ifndef _FANPSU_TRANSPORT_
#define _FANPSU_TRANSPORT_

#define FAN_NAME "fan"
#define PSU_NAME "psu"


typedef struct link_monitor{/*{{{*/

	fmd_hdl_t	*fpm_hdl;
	fmd_xprt_t	*fpm_xprt;
	id_t		fpm_timer;
	hrtime_t	fpm_interval;
	boolean_t	fpm_timer_istopo;
}fanpsu_monitor_t;/*}}}*/


#endif
