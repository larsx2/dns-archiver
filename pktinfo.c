#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "pktinfo.h"
#include "log.h"

pktinfo_t      *
pktinfo_init(void)
{
    pktinfo_t *info;

    info = calloc(sizeof(pktinfo_t), 1);

    log_debug("info = %p", info);

    return(info);
}

void
pktinfo_free(pktinfo_t * pkt)
{
    log_debug("pktinfo_free(%p)", pkt);
    if (!pkt) {
        return;
    }

    free(pkt);
}

pktinfo_t      *
pktinfo_read_pkt_a(const unsigned char *pkt, uint32_t len)
{
    int             l3_offset;
    struct ip      *ipv4_pkt = NULL;
    struct ip6_hdr *ipv6_pkt = NULL;
    uint8_t         ipver;
    uint32_t        ip_hl,
                    ip_proto;
    uint16_t        sport,
                    dport,
                    toff;
    unsigned char       *data;
    struct udphdr       *udp_pkt = NULL;
    struct tcphdr       *tcp_pkt = NULL;
    pktinfo_t           *pktinfo = NULL;
    const unsigned char *pkt_end;

    pkt_end =            (const unsigned char *)(pkt + len);
    l3_offset = 14;
    ipv4_pkt = (struct ip *)(pkt + l3_offset);
    ipv6_pkt = (struct ip6_hdr *)(pkt + l3_offset);
    ipver = ipv4_pkt->ip_v;
    pktinfo = NULL;

    switch (ipver) {
        case 4:
            if ((char *)((char *)ipv4_pkt + sizeof(struct ip)) >
                (char *)pkt_end) {
                return(NULL);
            }

            ip_hl = ipv4_pkt->ip_hl * 4;
            ip_proto = ipv4_pkt->ip_p;

            break;
        case 6:

            if ((char *)((char *)ipv6_pkt + sizeof(struct ip6_hdr)) >
                (char *)pkt_end) {
                return(NULL);
            }

            ip_hl = sizeof(struct ip6_hdr);
            ip_proto = ipv6_pkt->ip6_nxt;

            break;
        default:
            return(NULL);

    } /* switch */

    switch (ip_proto) {
        case IPPROTO_UDP:
            udp_pkt = (struct udphdr *)((unsigned char *)(ipv4_pkt) + ip_hl);

            if ((char *)((char *)udp_pkt + sizeof(struct udphdr)) >
                (char *)pkt_end) {
                return(NULL);
            }

            toff = sizeof(struct udphdr);
            sport = udp_pkt->uh_sport;
            dport = udp_pkt->uh_dport;

            data = (unsigned char *)((unsigned char *)udp_pkt + toff);
            break;
        case IPPROTO_TCP:
            tcp_pkt = (struct tcphdr *)((unsigned char *)(ipv4_pkt) + ip_hl);

            if ((char *)((char *)tcp_pkt + sizeof(struct tcphdr)) >
                (char *)pkt_end) {
                return(NULL);
            }

            toff = (tcp_pkt->th_off * 4);
            sport = tcp_pkt->th_sport;
            dport = tcp_pkt->th_dport;

            data = (unsigned char *)((unsigned char *)tcp_pkt + toff);
            break;
        default:
            return(NULL);
    } /* switch */

    pktinfo = pktinfo_init();
    pktinfo->ipver = ipver;
    pktinfo->ip_hl = ip_hl;
    pktinfo->ip_proto = ip_proto;
    pktinfo->sport = sport;
    pktinfo->dport = dport;
    pktinfo->toff = toff;
    pktinfo->data_len = pkt_end - data;

    if (ipv4_pkt) {
        pktinfo->ipv4_pkt = ipv4_pkt;
    }

    if (ipv6_pkt) {
        pktinfo->ipv6_pkt = ipv6_pkt;
    }

    if (pktinfo->data_len > 0) {
        pktinfo->data = data;
    }

    if (tcp_pkt) {
        pktinfo->tcp_pkt = tcp_pkt;
    }

    if (udp_pkt) {
        pktinfo->udp_pkt = udp_pkt;
    }

    return(pktinfo);
} /* pktinfo_read_pkt_a */
