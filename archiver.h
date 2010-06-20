#ifndef __ARCHIVER_H__
#define __ARCHIVER_H__

typedef enum {
    QUESTION,
    ANSWER
} query_type_t;


typedef struct {
    char   *key;
    uint8_t type;
    time_t  ts;
} associated_node_t;

typedef struct {
    query_type_t query_type;
    char        *key;
    GHashTable  *associated;
} archive_node_t;

int dns_archiver(GHashTable *, ldns_pkt *);
void associated_node_free(associated_node_t *node);
void archive_node_free(archive_node_t *node);

#endif
