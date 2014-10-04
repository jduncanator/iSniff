/*
 * Extract from Apple XNU Kernel
 * Copyright (c) 1999-2010 Apple Inc. All rights reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 */
#ifndef IPTAP_H
#define IPTAP_H

#pragma pack(push)
#pragma pack(1)

typedef struct iptap_hdr_t {
	uint32_t	hdr_length;
	uint8_t		version;
	uint32_t	length;
	uint8_t		type;
	uint16_t	unit;
	uint8_t		io;
	uint32_t	protocol_family;
	uint32_t	frame_pre_length;
	uint32_t	frame_pst_length;
	char		if_name[sizeof(char) * 16];
} iptap_hdr_t;

#pragma pack(pop)

#endif /* IPTAP_H */