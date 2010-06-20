/*
 * the idea of the archiver is to take a dns answer and do the following:
 *
 * ;; QUESTION SECTION:
 * ;www.google.com.			IN	A
 *
 * ;; ANSWER SECTION:
 * www.google.com.		604800	IN	CNAME	www.l.google.com.
 * www.l.google.com.	300	IN	A	209.85.225.103
 * www.l.google.com.	300	IN	A	209.85.225.99
 *
 * node key = www.google.com.
 * `-  val = CNAME www.l.google.com.
 * node key = www.l.google.com.
 * `-  val = 209.85.225.103
 * `-  val = 209.85.225.99
 *
 * If another response has the question of www.google.com:
 * ;; QUESTION SECTION:
 * ;www.google.com.      IN  A
 *
 * ;; ANSWER SECTION:
 * www.google.com.   604800  IN  CNAME www.l.google.com.
 * www.l.google.com. 300 IN  A 209.85.225.106
 * www.l.google.com. 300 IN  A 209.85.225.147
 *
 * We would have the structure of
 *
 * node key = www.google.com.
 * `- val  = CNAME www.l.google.com.
 * node key = www.l.google.com.
 * `- val  = 209.85.225.103
 * `- val  = 209.85.225.99
 * `- val  = 209.85.225.106
 * `- val  = 209.85.225.147
 *
 * The reverse of this data is also kept:
 *
 * node key = 209.85.225.103
 * `-  val = www.l.google.com.
 * node key = 209.85.225.99
 * `-  val = www.l.google.com.
 * node key = 209.85.225.106
 * `-  val = www.l.google.com.
 * node key = 209.85.225.147
 * `-  val = www.l.google.com.
 *
 * All this information can then be queried in a recursive nature.
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <ldns/ldns.h>
#include <glib.h>
#include <event.h>
#include "archiver.h"
#include "log.h"

static associated_node_t *
associated_node_new(const char *key, const uint8_t type, const time_t ts)
{
    associated_node_t *node;

    node = malloc(sizeof(associated_node_t));

    if (node == NULL) {
        return(NULL);
    }

    node->key  = strdup(key);
    node->type = type;
    node->ts   = ts;

    return(node);
}

void
archive_node_free(archive_node_t *node)
{
    if (node == NULL) {
        return;
    }

    if (node->key != NULL) {
        free(node->key);
    }

    if (node->associated != NULL) {
        g_hash_table_destroy(node->associated);
    }
}

void
associated_node_free(associated_node_t *node)
{
    if (node == NULL) {
        return;
    }

    if (node->key != NULL) {
        free(node->key);
    }

    free(node);
}


static archive_node_t *
archive_node_new(const char *key, uint32_t timeout, query_type_t query_type)
{
    archive_node_t *node;

    node = malloc(sizeof(archive_node_t));

    if (node == NULL) {
        return(NULL);
    }

    node->key         = strdup(key);
    node->query_type  = query_type;
    node->associated  = g_hash_table_new_full(g_str_hash,
                                              g_str_equal,
                                              NULL,
                                              (GDestroyNotify)associated_node_free);
    return(node);
}

archive_node_t *
archive_lookup(GHashTable *archive, const char *key)
{
    return((archive_node_t *)g_hash_table_lookup(archive, key));
}

associated_node_t *
archive_associated_lookup(archive_node_t *node, const char *key)
{
    return((associated_node_t *)g_hash_table_lookup(node->associated, key));
}

static associated_node_t *
associated_lookup_or_make_insert(GHashTable *archive, const char *key)
{
    associated_node_t *node;

    node = g_hash_table_lookup(archive, key);

    if (node == NULL) {
        node = associated_node_new(key, 0, time(NULL));

        if (node == NULL) {
            return(NULL);
        }

        g_hash_table_insert(archive, node->key, node);
    }

    return(node);
}


static archive_node_t *
node_lookup_or_make_insert(GHashTable *archive, const char *key,
                           query_type_t query_type)
{
    archive_node_t *node;

    node = archive_lookup(archive, key);

    if (node == NULL) {
        node = archive_node_new(key, 1800, query_type);

        if (node == NULL) {
            return(NULL);
        }

        g_hash_table_insert(archive, node->key, node);
    }

    return(node);
}

#if 0
static int
archive_lname_rname(GHashTable  *archive_hash,
                    ldns_rdf    *lname,
                    ldns_rdf    *rname,
                    ldns_buffer *buf)
{
    return(0);
}

static int
archive_list_lname(GHashTable   *archive_hash,
                   ldns_rr_list *list,
                   ldns_rdf     *lname,
                   ldns_buffer  *buf)
{
    return(0);
}
#endif

static int
archive_lname_list(GHashTable   *archive_hash,
                   ldns_rdf     *lname,
                   ldns_rr_list *list,
                   ldns_buffer  *buf)
{
    int             list_count;
    char           *lname_str;
    ldns_status     status;
    int             i;
    archive_node_t *lname_node = NULL;

    ldns_buffer_clear(buf);
    status = ldns_rdf2buffer_str(buf, lname);

    if (status != LDNS_STATUS_OK) {
        log_debug("ldns_rdf2buffer_str() returned error %d", status);
        return(-1);
    }

    list_count = ldns_rr_list_rr_count(list);
    lname_str  = ldns_buffer2str(buf);
    log_debug("%s", lname_str);

    if (lname_str == NULL) {
        log_debug("ldns_buffer2str(%p) returned null", buf);
        return(-1);
    }

    for (i = 0; i < list_count; i++) {
        ldns_rr  *rr;
        ldns_rdf *rname;
        char     *rname_str;
        int       data_offset = 0;

        ldns_buffer_clear(buf);

        /* so dns lname's are not always associated with
         *  the actual question. A question may be for blah.com
         *  but a lname can be stupid.com.
         *
         *  The issue becomes is that a caching nameserver may
         *  aggregate records together such is the case when a
         *  resolver returns a CNAME, it will then lookup the
         *  CNAME and plunk that into one response.
         *
         *  That's cool and all, but in the case of our sniffer
         *  we will treat all lname's as the real question, and
         *  all right names as answers for that question.
         *
         *  It servers a purpose within a sniffer like this,
         *  someone could be doing something a bit shady in that
         *  they give out an answer for one address, but then
         *  actually answer a completely different lname. */

        rr = ldns_rr_list_rr(list, i);

        switch (ldns_rr_get_type(rr)) {
            /* at the moment, we only really care about
             * rr's that have an addr or cname for the rname. */
            case LDNS_RR_TYPE_AAAA:
            case LDNS_RR_TYPE_A:
            case LDNS_RR_TYPE_CNAME:
                data_offset = 0;
                break;
            default:
                data_offset = -1;
                break;
        }

        if (data_offset == -1) {
            continue;
        }

        if (lname_node == NULL) {
            /* find our question in our hash table */
            /* if it doesn't exist, create it */
            lname_node =
                node_lookup_or_make_insert(archive_hash, lname_str, QUESTION);
        }

        /* now add this answer to the association hash */
        rname = ldns_rr_rdf(rr, data_offset);

        if (rname == NULL) {
            continue;
        }

        ldns_rdf2buffer_str(buf, rname);
        rname_str = ldns_buffer2str(buf);

        if (rname_str == NULL) {
            continue;
        }

        associated_lookup_or_make_insert(lname_node->associated, rname_str);

        /* now put the question as an answer into the archive hash */
        lname_node = node_lookup_or_make_insert(archive_hash, rname_str, ANSWER);
        associated_lookup_or_make_insert(lname_node->associated, lname_str);

    }

    return(0);
} /* archive_lname_list */


static int
archive(GHashTable *archive_hash,
        ldns_rr_list *questions,
        ldns_rr_list *answers,
        ldns_rr_list *authorities)
{
    ldns_buffer *dns_buffer;
    int          qa_rrcount;
    int          an_rrcount;
    int          au_rrcount;
    int          i;

    qa_rrcount = ldns_rr_list_rr_count(questions);
    an_rrcount = ldns_rr_list_rr_count(answers);
    au_rrcount = ldns_rr_list_rr_count(authorities);
    dns_buffer = ldns_buffer_new(LDNS_MIN_BUFLEN);

    log_debug("%d qa_rrcount", qa_rrcount);

    for (i = 0; i < qa_rrcount; i++) {
        ldns_rr  *question_rr;
        ldns_rdf *rdf_data;
        int       ret;

        question_rr = ldns_rr_list_rr(questions, i);
        rdf_data    = ldns_rr_owner(question_rr);

        log_debug("archive(): rdf_data = %p", rdf_data);

        /* plop all the answers into the correct archive_node_t's
         * associated_nodes hash. */
        ret = archive_lname_list(archive_hash, rdf_data, answers, dns_buffer);

        if (ret < 0) {
            log_debug("archive_lname_list() returned error");
        }
        /* archive_lname_list(archive_hash, rdf_data, authorities, dns_buffer); */
    }

    ldns_buffer_free(dns_buffer);
    return(0);
}

int
dns_archiver(GHashTable *archive_hash, ldns_pkt *dnspkt)
{
    ldns_rr_list *questions;
    ldns_rr_list *answers;
    ldns_rr_list *authorities;

    if (!ldns_pkt_qr(dnspkt)) {
        /* in our case, we only care about
         * answers, no questions allowed! */
        return(0);
    }

    if (!ldns_pkt_qdcount(dnspkt) || !ldns_pkt_ancount(dnspkt)) {
        /* no questions or answers */
        log_debug("dns_archiver() packet did not contain answer");
        return(0);
    }

    questions   = ldns_pkt_question(dnspkt);
    answers     = ldns_pkt_answer(dnspkt);
    authorities = ldns_pkt_authority(dnspkt);

    if (archive(archive_hash, questions, answers, authorities) < 0) {
        log_debug("dns_archiver(): archive() returned -1");
        return(-1);
    }

    return(0);
}
