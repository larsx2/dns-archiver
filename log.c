#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <glib.h>
#include "log.h"

void
logger(gchar *log_domain,
       GLogLevelFlags log_level,
       gchar * message, gpointer user_data)
{
    const char *level = NULL;
    int         i;
    time_t      stamp;
    struct tm   t;

#ifndef DEBUG
    if (log_level == G_LOG_LEVEL_DEBUG) {
        return;
    }
#endif

    if (!log_domain) {
        log_domain = "geo_pcap";
    }

    struct log_level_map {
        const char *name;
        int         mask;
    } log_level_mapping[] = {
        { "\033[31;1m", G_LOG_LEVEL_ERROR                                                                    },
        { "\033[31;1m", G_LOG_LEVEL_CRITICAL                                                                 },
        { "\033[35;1m", G_LOG_LEVEL_WARNING                                                                  },
        { "\033[33;1m", G_LOG_LEVEL_MESSAGE                                                                  },
        { "\033[32;1m", G_LOG_LEVEL_INFO                                                                     },
        { "\033[36;1m", G_LOG_LEVEL_DEBUG                                                                    },
        { NULL,         0                                                                                    }
    };

    for (i = 0; log_level_mapping[i].name != NULL; i++) {
        if (log_level & log_level_mapping[i].mask) {
            level = log_level_mapping[i].name;
            break;
        }
    }

    stamp = time(NULL);
    localtime_r(&stamp, &t);

    printf("[%02d%02d%04d %02d:%02d:%02d] %s%s\033[0m: %s\n",
           t.tm_mday, t.tm_mon + 1, t.tm_year + 1900, t.tm_hour, t.tm_min,
           t.tm_sec, level, log_domain, message);
} /* logger */
