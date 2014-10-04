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