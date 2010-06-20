#ifndef __ARCHIVER_H__
#define __ARCHIVER_H__

typedef struct {
    char    *key;
    uint8_t  type;
    time_t   ts;
} associated_node_t;

typedef struct {
    char        *key;
    GHashTable  *associated;
    struct event timeout;
} archive_node_t;

int dns_archiver(GHashTable *, ldns_pkt *);
void associated_node_free(associated_node_t *node);
void archive_node_free(archive_node_t *node);

#endif
