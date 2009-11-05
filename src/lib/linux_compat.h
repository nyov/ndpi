#ifndef __IPOQUE_LINUX_COMPAT_H__
#define __IPOQUE_LINUX_COMPAT_H__

struct iphdr {
#if BYTE_ORDER == LITTLE_ENDIAN
      uint8_t ihl:4, version:4;
#elif BYTE_ORDER == BIG_ENDIAN
      uint8_t version:4, ihl:4;
#else
# error "BYTE_ORDER must be defined"
#endif
      uint8_t tos;
      uint16_t tot_len;
      uint16_t id;
      uint16_t frag_off;
      uint8_t ttl;
      uint8_t protocol;
      uint16_t check;
      uint32_t saddr;
      uint32_t daddr;
};

struct tcphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#if BYTE_ORDER == LITTLE_ENDIAN
    uint16_t res1:4, doff:4, fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
#elif BYTE_ORDER == BIG_ENDIAN
    uint16_t doff:4, res1:4, cwr:1, ece:1, urg:1, ack:1, psh:1, rst:1, syn:1, fin:1;
#else
# error "BYTE_ORDER must be defined"
#endif  
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};

struct udphdr {
    uint16_t source;
    uint16_t dest;
    uint16_t len;
    uint16_t check;
};

#define ETH_P_IP	0x0800

struct ethhdr {
	unsigned char	h_dest[6];
	unsigned char	h_source[6];
	uint16_t		h_proto;
};

#endif
