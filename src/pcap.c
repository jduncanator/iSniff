#include <stdio.h>
#include "pcap.h"

int pcap_write_header(FILE *fp, int linktype, int snaplen)
{
	struct pcap_file_header hdr;

	hdr.magic = TCPDUMP_MAGIC;
	hdr.version_major = PCAP_VERSION_MAJOR;
	hdr.version_minor = PCAP_VERSION_MINOR;

	hdr.thiszone = 0;
	hdr.snaplen = snaplen;
	hdr.sigfigs = 0;
	hdr.linktype = linktype;

	if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1)
		return -1;

	return 0;
}

int pcap_write_packet(FILE *fp, const struct pcap_sf_pkthdr *hdr, const char *sp)
{
	(void)fwrite(hdr, sizeof(struct pcap_sf_pkthdr), 1, fp);
	(void)fwrite(sp, hdr->caplen, 1, fp);
	return 0;
}
