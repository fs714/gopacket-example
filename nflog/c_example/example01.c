#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <libnetfilter_log/libnetfilter_log.h>

static int print_pkt(struct nflog_data *data)
{
    struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(data);
    uint32_t mark = nflog_get_nfmark(data);
    uint32_t indev = nflog_get_indev(data);
    uint32_t outdev = nflog_get_outdev(data);
    struct timeval tv;
    memset(&tv, 0, sizeof(tv));
    int ts_ret = nflog_get_timestamp(data, &tv);
    char *prefix = nflog_get_prefix(data);
    char *payload;
    int payload_len = nflog_get_payload(data, &payload);

    printf("------\n");

    if (ph)
    {
        printf("hw_protocol=0x%04x hook=%u ", ntohs(ph->hw_protocol), ph->hook);
    }

    printf("mark=%u ", mark);

    if (indev > 0)
        printf("indev=%u ", indev);

    if (outdev > 0)
        printf("outdev=%u ", outdev);

    if (ts_ret == 0)
    {
        time_t nowtime;
        struct tm *nowtm;
        char tmbuf[64], buf[64];
        nowtime = tv.tv_sec;
        nowtm = localtime(&nowtime);
        strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
        printf("ts = %s.%06ld ", tmbuf, tv.tv_usec);
    }
    else
    {
        printf("ts = failed err = %d nflog_err = %d ", errno, nflog_errno);
    }

    if (prefix)
    {
        printf("prefix=\"%s\" ", prefix);
    }

    if (payload_len >= 0)
        printf("payload_len=%d ", payload_len);

    fputc('\n', stdout);

    return 0;
}

static int cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg, struct nflog_data *nfa, void *data)
{
    print_pkt(nfa);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc == 1)
    {
        printf("nflog group id is required\n");
        exit(1);
    }
    else if (argc > 2)
    {
        printf("too many arguments supplied\n");
        exit(1);
    }

    char *p;
    uint16_t groupId;

    errno = 0;
    long conv = strtol(argv[1], &p, 10);

    if (errno != 0 || *p != '\0' || conv > INT_MAX || conv < INT_MIN)
    {
        printf("invalid group id\n");
        exit(1);
    }
    else
    {
        groupId = conv;
        printf("start for nflog group id %d\n", groupId);
    }

    struct nflog_handle *h;
    struct nflog_g_handle *qh;
    int rv, fd;
    char buf[4 * 1024 * 1024];

    h = nflog_open();
    if (!h)
    {
        printf("error during nflog_open()\n");
        exit(1);
    }

    if (nflog_bind_pf(h, AF_INET) < 0)
    {
        printf("error during nflog_bind_pf()\n");
        exit(1);
    }

    qh = nflog_bind_group(h, groupId);
    if (!qh)
    {
        printf("error during nflog_bind_group()\n");
        exit(1);
    }

    if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0)
    {
        printf("error during nflog_set_mode()\n");
        exit(1);
    }

    fd = nflog_fd(h);

    nflog_callback_register(qh, &cb, NULL);

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0)
    {
        printf("pkt received (len=%u)\n", rv);

        nflog_handle_packet(h, buf, rv);
    }

    nflog_unbind_group(qh);
    nflog_close(h);

    return EXIT_SUCCESS;
}