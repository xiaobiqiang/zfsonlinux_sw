#ifndef __LHL_DEBUG_H_
#define __LHL_DEBUG_H_

#include <stdio.h>
#include <syslog.h>

extern FILE *log_file;
extern int log_step;
extern void log_null(FILE *, ...);

/* #define ENABLE_LOG */

#define STRING(x) #x
#define STRINGSTRING(x) STRING(x)

#define location __FILE__ " :"STRINGSTRING(__LINE__)

#if defined(DMESG)
    #undef DMESG
#endif

#define DMESG(...) syslog(LOG_ERR | LOG_DAEMON, __VA_ARGS__)

#define log_record(handle, ...) \
    do{ \
        if(handle){ \
            fprintf(log_file, "%s  ", location); \
            fprintf(log_file, __VA_ARGS__); \
            fflush(log_file); \
        } \
    }while(0)

#ifdef ENABLE_LOG
    #define LOG(...) log_record(log_file, __VA_ARGS__)
#else
    #define LOG(...) log_null(log_file, __VA_ARGS__)
#endif

#endif
