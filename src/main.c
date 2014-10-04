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
#include <stdlib.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>

#include <plist/plist.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/property_list_service.h>

#include "pcap.h"
#include "iftap.h"

#ifdef WIN32
#include <Winsock2.h>
#else
#include <netinet/in.h>
#endif

char *outfile = NULL;
char *udid = NULL;

static char list_udid = 0;
static char quit_flag = 0;

/* 
 * str_is_udid from ideviceinstaller.c
 * Copyright (C) 2010 Nikias Bassen <nikias@gmx.li>
 * Licensed under the GNU General Public License Version 2
 */
static int str_is_udid(const char* str)
{
	const char allowed[] = "0123456789abcdefABCDEF";

	/* handle NULL case */
	if (str == NULL)
		return -1;

	int length = strlen(str);

	/* verify length */
	if (length != 40)
		return -1;

	/* check for invalid characters */
	while(length--) {
		/* invalid character in udid? */
		if (strchr(allowed, str[length]) == NULL) {
			return -1;
		}
	} 

	return 0;
}

static void handle_interrupt(int sig)
{
	fprintf(stderr, "Closing...\n");
	quit_flag = 1;
}

static void print_usage(int argc, char **argv)
{
	char *name = NULL;

	name = strrchr(argv[0], '/');
	printf("Usage: %s [OPTIONS] [PCAPFILE]\n", (name ? name + 1 : argv[0]));
	printf("Capture packets on a connected iDevice.\n\n");
	printf("  If PCAPFILE is passed, write the raw packets to file\n"
		   "  rather than writing to STDOUT.\n\n");
	printf
		("  -u, --udid UDID\tTarget specific device by its 40-digit device UDID.\n"
		 "  -l, --list\t\tlist UDID of all attached devices\n"
		 "  -h, --help\t\tprints usage information\n"
		 "  -d, --debug\t\tenable communication debugging\n" "\n");
}

static void parse_opts(int argc, char **argv)
{
	static struct option longopts[] = {
		{"help", 0, NULL, 'h'},
		{"udid", 0, NULL, 'u'},
		{"list", 0, NULL, 'l'},
		{"debug", 0, NULL, 'd'},
		{NULL, 0, NULL, 0}
	};
	int c;

	while (1) {
		c = getopt_long(argc, argv, "hlu:d", longopts,
						(int *) 0);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 'h':
			print_usage(argc, argv);
			exit(0);
		case 'u':
			if (str_is_udid(optarg) == 0) {
				udid = strdup(optarg);
				break;
			}
			fprintf(stderr, "[ERROR] Invalid UDID specified\n");
			print_usage(argc, argv);
			exit(2);
			break;
		case 'l':
			list_udid = 1;
			break;
		case 'd':
			idevice_set_debug_level(1);
			break;
		default:
			print_usage(argc, argv);
			exit(2);
		}
	}

	outfile = argv[optind];

	if (argc - optind > 1) {
		print_usage(argc, argv);
		exit(2);
	}
}

int main (int argc, char *argv[])
{
	parse_opts(argc, argv);

	idevice_error_t err = IDEVICE_E_UNKNOWN_ERROR;

	idevice_t device = NULL;
	lockdownd_client_t lockdown = NULL;
	lockdownd_service_descriptor_t service = NULL;
	property_list_service_client_t pcap_client = NULL;

	pcap_t *pd = NULL;
	pcap_dumper_t *pdumper = NULL;

	if(list_udid) {
		int i;
		char **devices = NULL;
		char *device_name = NULL;

		if (idevice_get_device_list(&devices, &i) < 0) {
			fprintf(stderr, "[ERROR] Unable to retrieve device list!\n");
			return -1;
		}

		for (i = 0; devices[i] != NULL; i++) {
			idevice_new(&device, devices[i]);
			if (!device) {
				fprintf(stderr, "[ERROR] No device with UDID %s connected.\n", devices[i]);
				return -2;
			}
			if (LOCKDOWN_E_SUCCESS != lockdownd_client_new(device, &lockdown, "iSniff")) {
				idevice_free(device);
				fprintf(stderr, "[ERROR] Connecting to device failed!\n");
				return -2;
			}

			if ((LOCKDOWN_E_SUCCESS != lockdownd_get_device_name(lockdown, &device_name)) || !device_name) {
				lockdownd_client_free(lockdown);
				idevice_free(device);
				fprintf(stderr, "[ERROR] Could not get device name!\n");
				return -2;
			}

			lockdownd_client_free(lockdown);
			idevice_free(device);
			
			printf("%s - %s\n", devices[i], device_name);

			if (device_name) {
				free(device_name);
			}
		}

		idevice_device_list_free(devices);
		return 0;
	}

	err = idevice_new(&device, udid);
	if (err != IDEVICE_E_SUCCESS) {
		if (udid) {
			printf("No device found with udid %s, is it plugged in?\n", udid);
		} else {
			printf("No device found, is it plugged in?\n");
		}
		return -1;
	}

	if(!udid) {
		idevice_get_udid(device, &udid);
	}
	
	if (LOCKDOWN_E_SUCCESS != lockdownd_client_new_with_handshake(device, &lockdown, "iSniff")) {
		idevice_free(device);
		printf("Could not connect to lockdownd.\n");
		return -1;
	}

	if(udid) {
		fprintf(stderr, "Connected to %s\n", udid);
		free(udid);
	}

	err = lockdownd_start_service(lockdown, "com.apple.pcapd", &service);
	if (err != LOCKDOWN_E_SUCCESS || !(service && service->port)) {
		idevice_free(device);
		printf("Could not start com.apple.pcapd\n");
		return -1;
	}
	lockdownd_client_free(lockdown);

	err = property_list_service_client_new(device, service, &pcap_client);
	if (err != PROPERTY_LIST_SERVICE_E_SUCCESS) {
		idevice_free(device);
		printf("Could not connect to service %s! Port: %i, Err: %i\n", "com.apple.pcapd", service->port, err);
		return -1;
	}
	lockdownd_service_descriptor_free(service);

	if(!outfile) {
		outfile = "-";
	}

	pd = pcap_open_dead(DLT_EN10MB, 65535);
	pdumper = pcap_dump_open(pd, outfile);

	plist_t result = NULL;
	iptap_hdr_t *tap_hdr = NULL;
	struct pcap_pkthdr pcap_hdr;

	signal(SIGINT, handle_interrupt);
	signal(SIGTERM, handle_interrupt);

	while(1) {
		property_list_service_receive_plist(pcap_client, &result);

		char* buff = NULL;
		uint64_t length = 0;
		plist_get_data_val(result, &buff, &length);
		plist_free(result);

		tap_hdr = (iptap_hdr_t*)buff;
		
		gettimeofday(&pcap_hdr.ts, NULL);
		pcap_hdr.caplen = ntohl(tap_hdr->length);
		pcap_hdr.len = ntohl(tap_hdr->length);

		pcap_dump((char*)pdumper, &pcap_hdr, (buff + ntohl(tap_hdr->hdr_length)));
		pcap_dump_flush(pdumper);

		free(buff);

		if(quit_flag) break;
	}

	pcap_close(pd);
	pcap_dump_close(pdumper);
	property_list_service_client_free(pcap_client);
	idevice_free(device);

	return 0;
}