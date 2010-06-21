#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/queue.h>

#include <event.h>
#include <evhttp.h>
#include <glib.h>
#include <ldns/ldns.h>

#include "archiver.h"
#include "log.h"

static gboolean
fill_all_questions(const char *key, archive_node_t *archive_node,
                   struct evbuffer *buf)
{
    if (archive_node->query_type == QUESTION) {
        evbuffer_add_printf(buf, "%s\n", key);
    }

    return(FALSE);
}

static gboolean
fill_all_answers(const char *key, archive_node_t *archive_node,
                 struct evbuffer *buf)
{
    if (archive_node->query_type == ANSWER) {
        evbuffer_add_printf(buf, "%s\n", key);
    }

    return(FALSE);
}

static gboolean
fill_answers_for_q(const char *key, associated_node_t *node,
                   struct evbuffer *buf)
{
    evbuffer_add_printf(buf, "%s\n", key);
    return(FALSE);
}

static void
httpd_error(struct evhttp_request *req, GHashTable *archive)
{
    struct evbuffer *buf;

    buf = evbuffer_new();

    evbuffer_add_printf(buf, "go away");
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

static void
httpd_disp_questions(struct evhttp_request *req, GHashTable *archive)
{
    struct evbuffer *buf;

    buf = evbuffer_new();
    g_hash_table_foreach(archive, (GHFunc)fill_all_questions, buf);
    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evbuffer_free(buf);
}

static void
httpd_disp_answers(struct evhttp_request *req, GHashTable *archive)
{
    struct evbuffer *buf;
    struct evkeyvalq args;
    char            *zone_key;

    TAILQ_INIT(&args);
    buf = evbuffer_new();

    evhttp_parse_query(req->uri, &args);

    zone_key = (char *)evhttp_find_header(&args, "q");

    if (zone_key == NULL) {
        zone_key = "All answers";
        g_hash_table_foreach(archive, (GHFunc)fill_all_answers, buf);
    } else {
        archive_node_t *archive_node;

        archive_node = archive_lookup(archive, zone_key);

        if (archive_node == NULL) {
            zone_key = "not found..";
        } else {
            g_hash_table_foreach(archive_node->associated,
                                 (GHFunc)fill_answers_for_q, buf);
        }
    }

    evhttp_send_reply(req, HTTP_OK, "OK", buf);
    evhttp_clear_headers(&args);
    evbuffer_free(buf);
}

int
webserver_init(const char *bind_addr, const int port, GHashTable *archive)
{
    struct evhttp *httpd;

    httpd = evhttp_start(bind_addr, port);

    if (httpd == NULL) {
        return(-1);
    }

    evhttp_set_cb(httpd, "/questions", (void *)httpd_disp_questions, archive);
    evhttp_set_cb(httpd, "/answers", (void *)httpd_disp_answers, archive);
    evhttp_set_gencb(httpd, (void *)httpd_error, archive);

    return(0);
}

