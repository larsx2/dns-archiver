#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#define __FAVOR_BSD
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <pcap.h>
#include <event.h>
#include <ldns/ldns.h>
#include <glib.h>
#include "log.h"
#include "pktinfo.h"
#include "archiver.h"

typedef struct {
    const char  *bpf;
    const char  *iface;
    int          snaplen;
    pcap_t      *desc;
    struct event event;
} pcap_cfg_t;

GHashTable *archive;

void
packet_handler(const pcap_cfg_t *pcap_cfg,
               const struct pcap_pkthdr *hdr,
               const unsigned char *pkt)
{
    pktinfo_t  *decoded_pkt;
    ldns_pkt   *decoded_dns;
    ldns_status status;

    decoded_pkt = pktinfo_read_pkt_a(pkt, hdr->caplen);

    if (decoded_pkt == NULL) {
        return;
    }

    status = ldns_wire2pkt(&decoded_dns,
                           decoded_pkt->data,
                           decoded_pkt->data_len);

    if (status != LDNS_STATUS_OK) {
        pktinfo_free(decoded_pkt);
        return;
    }

    dns_archiver(archive, decoded_dns);

    pktinfo_free(decoded_pkt);
}

void
ev_packet_handler(int sock, short which, pcap_cfg_t *pcap_cfg)
{
    pcap_dispatch(pcap_cfg->desc, 1,
                  (void *)packet_handler, (void *)pcap_cfg);
}

int
pcap_init(pcap_cfg_t *cfg)
{
    struct bpf_program filterp;
    bpf_u_int32        netp;
    bpf_u_int32        maskp;
    char               err[PCAP_ERRBUF_SIZE];
    int                pcap_fd;
    pcap_t            *pcap_desc;

    if (pcap_lookupnet(cfg->iface, &netp, &maskp, err) < 0) {
        log_error("pcap_lookupnet: %s", err);
        return(-1);
    }

    pcap_desc = pcap_open_live(cfg->iface, cfg->snaplen, 1, 0, err);

    if (pcap_desc == NULL) {
        log_error("pcap_open_live: %s", err);
        return(-1);
    }

    if (cfg->bpf != NULL) {
        if (pcap_compile(pcap_desc, &filterp, cfg->bpf, 0, netp) < 0) {
            log_error("pcap_compile error");
            return(-1);
        }

        pcap_setfilter(pcap_desc, &filterp);
    }

    if (pcap_setnonblock(pcap_desc, 1, err) < 0) {
        log_error("pcap_setnonblock: %s", err);
        return(-1);
    }

    pcap_fd = pcap_get_selectable_fd(pcap_desc);

    if (pcap_fd <= 0) {
        log_error("pcap_get_selectable_fd: %s", err);
        return(-1);
    }

    cfg->desc = pcap_desc;

    event_set(&cfg->event, pcap_fd, EV_READ | EV_PERSIST,
              (void *)ev_packet_handler, cfg);
    event_add(&cfg->event, 0);

    return(0);
} /* pcap_init */


int main(int argc, char **argv)
{
    pcap_cfg_t pcap_cfg;

    g_log_set_default_handler((GLogFunc)logger, NULL);

    pcap_cfg.bpf     = "src port 53";
    pcap_cfg.iface   = "eth0";
    pcap_cfg.snaplen = 65535;

    event_init();
    pcap_init(&pcap_cfg);

    archive = g_hash_table_new(g_str_hash, g_str_equal);

    event_loop(0);

    return(0);
}

