/*
 * iSniff
 * Command line interface to use a device's remote packet capture service
 *
 * Copyright (C) 2014 jduncanator
 *
 * Licensed under the GNU General Public License Version 2
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more profile.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 
 * USA
 */



#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>
#include <Winsock2.h>

#include <libimobiledevice/property_list_service.h>
#include <libimobiledevice/libimobiledevice.h>
#include <plist/plist.h>

#include "pcap.h"
#include "iftap.h"

int main (int argc, char *argv[])
{
	//printf("Sizeof(uint32): %i\n", sizeof(uint32_t));

	idevice_error_t ret = IDEVICE_E_UNKNOWN_ERROR;

	idevice_t device = NULL;
	ret = idevice_new(&device, NULL);
	if (ret != IDEVICE_E_SUCCESS) {
		//printf("No device found, is it plugged in?\n");
		return -1;
	}

	char* udid = NULL;
	idevice_get_udid(device, &udid);
	if(udid) {
		//printf("Connected to %s\n", udid);
	}

	lockdownd_client_t lockdown = NULL;
	if (lockdownd_client_new_with_handshake(device, &lockdown, "isniff") != LOCKDOWN_E_SUCCESS) {
		//printf("Could not connect to lockdownd.\n");
		idevice_free(device);
		return -1;
	}

	lockdownd_service_descriptor_t service = NULL;
	ret = lockdownd_start_service(lockdown, "com.apple.pcapd", &service);
	if (ret != LOCKDOWN_E_SUCCESS || !(service && service->port)) {
		//printf("Could not start com.apple.pcapd.\n");
		return -1;
	}
	lockdownd_client_free(lockdown);

	property_list_service_client_t client = NULL;
	ret = property_list_service_client_new(device, service, &client);
	if (ret != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		//printf("Could not connect to service %s! Port: %i, Err: %i\n", "com.apple.pcapd", service->port, ret);
		return -1;
	}
	lockdownd_service_descriptor_free(service);

	pcap_t *pd;
    pcap_dumper_t *pdumper;

    pd = pcap_open_dead(DLT_EN10MB, 65535 /* snaplen */);
    // Create the output file.
    pdumper = pcap_dump_open(pd, "-");

	// Loop and receive all the packets
	while(1) {
		plist_t result = NULL;
		char *plist_xml = NULL;
		uint32_t size = 0;
		property_list_service_receive_plist(client, &result);
				
		//plist_to_xml(result, &plist_xml, &size);
		//fwrite(plist_xml, size, sizeof(char), stdout);

		plist_type type = plist_get_node_type(result);
		char* buff = NULL;
		uint64_t length = 0;
		plist_get_data_val(result, &buff, &length);

		iptap_hdr_t *tap_hdr = (iptap_hdr_t*)buff;
		//printf("Header length: %i\n", ntohl(tap_hdr->hdr_length));
		//printf("Packet length: %i\n", ntohl(tap_hdr->length));

		struct pcap_pkthdr hdr;
		gettimeofday (&hdr.ts, NULL);
		hdr.caplen = hdr.len = ntohl(tap_hdr->length);

		//printf("Buffer pointer: 0x%i\nPacket pointer: 0x%i\n", buff, (buff + ntohl(tap_hdr->hdr_length)));
		pcap_dump(pdumper, &hdr, (buff + ntohl(tap_hdr->hdr_length)));
		pcap_dump_flush(pdumper);
		plist_free(result);
	}

	pcap_close(pd);
    pcap_dump_close(pdumper);
	return 0;
}