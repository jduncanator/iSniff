#ifndef isniff_pcap_h
#define isniff_pcap_h

#include <stdint.h>
#ifdef WIN32
#include <Winsock2.h>
#else
#include <sys/time.h>
#endif

#define TCPDUMP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define DLT_EN10MB 1

struct pcap_timeval {
	int32_t tv_sec;
	int32_t tv_usec;
};

struct pcap_file_header {
	uint32_t magic;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;	/* gmt to local correction */
	uint32_t sigfigs;	/* accuracy of timestamps */
	uint32_t snaplen;	/* max length saved portion of each pkt */
	uint32_t linktype;	/* data link type (LINKTYPE_*) */
};

struct pcap_sf_pkthdr {
    struct pcap_timeval ts;	/* time stamp */
    uint32_t caplen;	/* length of portion present */
    uint32_t len;		/* length this packet (off wire) */
};

int pcap_write_header(FILE *, int, int);
int pcap_write_packet(FILE *, const struct pcap_sf_pkthdr *, const char *);

#endif