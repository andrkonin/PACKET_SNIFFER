#ifndef SNIFFER_H
#define SNIFFER_H

#include <QMainWindow>
#include <QTextEdit>

#ifdef WIN32

#else
    #include <GeoIP.h>
#endif

#define APP_NAME
#define APP_DESC
#define APP_COPYRIGHT
#define APP_DISCLAIMER

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define BUFSIZE 1518

#define SNAP_LEN 1518

#define SIZE_ETHERNET 14

#define ETHER_ADDR_LEN	6

struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];
        u_char  ether_shost[ETHER_ADDR_LEN];
        u_short ether_type;
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;
        u_char  ip_tos;
        u_short ip_len;
        u_short ip_id;
        u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char  ip_ttl;
        u_char  ip_p;
        u_short ip_sum;
        struct  in_addr ip_src,ip_dst;
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;
        u_short th_dport;
        tcp_seq th_seq;
        tcp_seq th_ack;
        u_char  th_offx2;
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;
        u_short th_sum;
        u_short th_urp;
};


class SNIFFER : public QMainWindow
{
    Q_OBJECT

public:

    SNIFFER();
    QString result;
    QString str;
    bool error;


signals:

    void onLoad();

public slots:

    void open(char *INAME);
    void close();
    void update();
    void clear();
    void save(QString fileName);

private slots:

private:

    void
            got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

    void
            print_payload(const u_char *payload, int len);

    void
            print_hex_ascii_line(const u_char *payload, int len, int offset);

    int num_packets;
    pcap_t *handle;
    //char dev[]="eth1";
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char *filter_exp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_pkthdr header;
    const u_char *packet;
    char *dev;
    bool interface;
    QTextEdit *status;
    //QLineEdit *status;
    long pcnt;
    char txtstr[100];
    const char *scountry;
    const char *dcountry;
    QString country;
    struct tm *ltime;
    char timestr[16];
    char timeS[20];

#ifdef WIN32

#else
    GeoIP *gi;
#endif


};
#endif // SNIFFER_H
