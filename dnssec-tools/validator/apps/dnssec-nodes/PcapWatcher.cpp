#include "PcapWatcher.h"

#include <validator/validator-config.h>
#include "validator/resolver.h"

#include <qdebug.h>

#include <sys/types.h>
#include <arpa/inet.h>
typedef u_int32_t tcp_seq;

/* standard libpcap sniffing structures */
#define ETHER_ADDR_LEN	6
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

#define TYPE_IPv4 0x800
#define TYPE_IPv6 0x86DD

#define TYPE_UDP 17
#define TYPE_TCP 6

#define UDP_HEADER_SIZE 8

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* IPv6 header */
struct sniff_ipv6 {
    uint32_t        ip_vtcfl;   /* version << 4 then traffic class and flow label */
    uint16_t        ip_len;     /* payload length */
    uint8_t         ip_nxt;     /* next header (protocol) */
    uint8_t         ip_hopl;    /* hop limit (ttl) */
    struct in6_addr ip_src, ip_dst;     /* source and dest address */
};
#define IPV6_VERSION(ip)          (ntohl((ip)->ip_vtcfl) >> 28)

/* TCP header */
struct sniff_tcp {
    u_short th_sport;	/* source port */
    u_short th_dport;	/* destination port */
    tcp_seq th_seq;		/* sequence number */
    tcp_seq th_ack;		/* acknowledgement number */

    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

struct sniff_udp {
    u_short udp_sport; /* source port */
    u_short udp_dport; /* destination port */
    u_short udp_hlen;	 /* Udp header length*/
    u_short udp_chksum;	 /* Udp Checksum */
};

PcapWatcher::PcapWatcher(QObject *parent) :
    QThread(parent), m_filterString("port 53"), m_deviceName(""), m_pcapHandle(0), m_timer(), counter(0)
{
}

QString PcapWatcher::deviceName()
{
    return m_deviceName;
}

void PcapWatcher::setDeviceName(const QString &deviceName)
{
    m_deviceName = deviceName;
}

void PcapWatcher::openDevice()
{
    bpf_u_int32 mask, net;
    qDebug() << "opening device: " << deviceName();

    closeDevice();

    if (pcap_lookupnet(m_deviceName.toAscii().data(), &net, &mask, m_errorBuffer)) {
        qWarning() << tr("could not get netmask for device: %s").arg(m_deviceName);
        emit failedToOpenDevice(tr("could not get netmask for device: %s").arg(m_deviceName));
        return;
    }

    m_pcapHandle = pcap_open_live(m_deviceName.toAscii().data(), BUFSIZ, 1, 100, m_errorBuffer);
    if (!m_pcapHandle) {
        // TODO: do something on error
        qWarning() << "failed to open the device: " << QString(m_errorBuffer);
        emit failedToOpenDevice(QString(m_errorBuffer));
        return;
    }

    if (m_filterString.length() > 0) {
        if (pcap_compile(m_pcapHandle, &m_filterCompiled, m_filterString.toAscii().data(), 1, mask) < -1) {
            emit failedToOpenDevice(tr("failed to parse the filter: %s").arg(pcap_geterr(m_pcapHandle)));
            return;
        }
    }

    if (pcap_setfilter(m_pcapHandle, &m_filterCompiled) < -1) {
        emit failedToOpenDevice(tr("failed to install the filter: %s").arg(pcap_geterr(m_pcapHandle)));
        return;
    }
    m_timer.singleShot(100, this, SLOT(processPackets()));
}

void PcapWatcher::run() {
    emit addNode("foo.bar.com");
    emit addNodeData("baz.ack.bar.com", DNSData("A", DNSData::UNKNOWN));
    connect(&m_timer, SIGNAL(timeout()), this, SLOT(processPackets()));
    exec();
}

void PcapWatcher::closeDevice()
{
    if (m_pcapHandle) {
        pcap_close(m_pcapHandle);
        m_pcapHandle = 0;
    }
}

void PcapWatcher::processPackets()
{
    const u_char       *packet;
    struct pcap_pkthdr  header;
    unsigned int size_ip;
    unsigned int size_tcp;

    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const struct sniff_udp *udp; /* The TCP header */
    const u_char *payload; /* Packet payload */
    size_t        payload_len;

    if (m_pcapHandle) {
        // process packets received from pcap
        while(packet = pcap_next(m_pcapHandle, &header)) {
            int             rrnum = 0;
            ns_msg          handle;
            ns_rr           rr;

            udp = 0;
            tcp = 0;
            /* received a packet, now decode it */
            ethernet = (struct sniff_ethernet*)(packet);

            if (ntohs(ethernet->ether_type) == TYPE_IPv4) {
                ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
                size_ip = IP_HL(ip)*4;
                if (size_ip < 20) {
                    printf("   * Invalid IP header length: %u bytes\n", size_ip);
                    continue;
                }
                if (ip->ip_p == TYPE_UDP) {
                    udp = (struct sniff_udp *) (packet + SIZE_ETHERNET + size_ip);
                } else if (ip->ip_p == TYPE_TCP) {
                    tcp = (struct sniff_tcp *) (packet + SIZE_ETHERNET + size_ip);
                }
            } else if (ntohs(ethernet->ether_type) == TYPE_IPv6) {
                /* XXX: ipv6 */
                continue;
            } else {
                /* The magical other protocols */
                continue;
            }

            /* TCP processing */
            /* XXX: UDP */
            counter++;
            if (tcp) {
                tcp = (struct sniff_tcp*) (packet + SIZE_ETHERNET + size_ip);
                size_tcp = TH_OFF(tcp)*4;
                if (size_tcp < 20) {
                    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                    continue;
                }
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
                payload_len = header.len - (SIZE_ETHERNET + size_ip + size_tcp);
            } else if (udp) {
                udp = (struct sniff_udp *) (packet + SIZE_ETHERNET + size_ip);
                payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + UDP_HEADER_SIZE);
                payload_len = header.len - (SIZE_ETHERNET + size_ip + UDP_HEADER_SIZE);
            } else {
                qWarning() << "unknown protocol (shouldn't get here)";
                continue;
            }

            if (ns_initparse(payload, payload_len, &handle) < 0) {
                qWarning() << tr("Fatal internal error: failed to init parser");
                continue;
            }

            for (;;) {
                if (ns_parserr(&handle, ns_s_an, rrnum, &rr)) {
                    if (errno != ENODEV) {
                        /* parse error */
                        qWarning() << tr("failed to parse a returned additional RRSET");
                        continue;
                    }
                    break; /* out of data */
                }

                emit addNodeData(ns_rr_name(rr), DNSData(p_sres_type(ns_rr_type(rr)), DNSData::UNKNOWN));

                //if (ns_rr_type(rr) == ns_t_a) {
                    /* insert stuff here */
                //}
                rrnum++;
            }

        }


        // wait a while till the next packet
        m_timer.singleShot(100, this, SLOT(processPackets()));
    }
}
