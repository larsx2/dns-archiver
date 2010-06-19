#include <glib.h>
#define log_message(fmt, s...) do { g_log(__FUNCTION__, G_LOG_LEVEL_MESSAGE, fmt, ## s); } while (0)
#define log_error(fmt, s...) do { g_log(__FUNCTION__, G_LOG_LEVEL_ERROR, fmt, ## s); } while (0);
#define log_debug(fmt, s...) do { g_log(__FUNCTION__, G_LOG_LEVEL_DEBUG, fmt, ## s); } while (0);

void
logger(gchar *log_domain,
       GLogLevelFlags log_level,
       gchar *message,
       gpointer user_data);
