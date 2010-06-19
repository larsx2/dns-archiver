#define __FAVOR_BSD
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>

typedef struct pktinfo {
    struct ip      *ipv4_pkt;
    struct ip6_hdr *ipv6_pkt;
    uint8_t         ipver;
    uint32_t        ip_hl;
    uint32_t        ip_proto;
    uint16_t        sport;
    uint16_t        dport;
    uint16_t        toff;
    struct udphdr  *udp_pkt;
    struct tcphdr  *tcp_pkt;
    unsigned char  *data;
    uint32_t        data_len;
} pktinfo_t;

pktinfo_t *pktinfo_init(void);
void       pktinfo_free(pktinfo_t *);
pktinfo_t *pktinfo_read_pkt_a(const unsigned char *, uint32_t);

