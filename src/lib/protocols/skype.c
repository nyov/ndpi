/*
 * skype.c
 *
 * Copyright (C) 2011-15 - ntop.org
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_SKYPE

struct net_mask {
  u_int32_t network, mask;
};

static struct net_mask asn8075[] = {
  { 0x17600000, 0xFFFC0000 /* 14 */},
  { 0x17613000, 0xFFFFF000 /* 20 */},
  { 0x17614000, 0xFFFFE000 /* 19 */},
  { 0x17616000, 0xFFFFE000 /* 19 */},
  { 0x17622000, 0xFFFFF800 /* 21 */},
  { 0x17622800, 0xFFFFFC00 /* 22 */},
  { 0x17623800, 0xFFFFF800 /* 21 */},
  { 0x17624000, 0xFFFFC000 /* 18 */},
  { 0x17640000, 0xFFFE0000 /* 15 */},
  { 0x17660000, 0xFFFF0000 /* 16 */},
  { 0x17674000, 0xFFFFC000 /* 18 */},
  { 0x17678000, 0xFFFF8000 /* 17 */},
  { 0x40040000, 0xFFFFC000 /* 18 */},
  { 0x41340000, 0xFFFC0000 /* 14 */},
  { 0x4134A000, 0xFFFFE000 /* 19 */},
  { 0x41362800, 0xFFFFFF00 /* 24 */},
  { 0x41364200, 0xFFFFFE00 /* 23 */},
  { 0x41364400, 0xFFFFFF00 /* 24 */},
  { 0x41365200, 0xFFFFFF00 /* 24 */},
  { 0x41365500, 0xFFFFFF00 /* 24 */},
  { 0x41365A00, 0xFFFFFE00 /* 23 */},
  { 0x41372C00, 0xFFFFFF00 /* 24 */},
  { 0x41377500, 0xFFFFFF00 /* 24 */},
  { 0x4137E600, 0xFFFFFF00 /* 24 */},
  { 0x4137E700, 0xFFFFFF00 /* 24 */},
  { 0x42779000, 0xFFFFF000 /* 20 */},
  { 0x46250000, 0xFFFF8000 /* 17 */},
  { 0x46258000, 0xFFFFC000 /* 18 */},
  { 0x46259600, 0xFFFFFE00 /* 23 */},
  { 0x5EF54000, 0xFFFFC000 /* 18 */},
  { 0x5EF54C00, 0xFFFFFE00 /* 23 */},
  { 0x5EF55200, 0xFFFFFF00 /* 24 */},
  { 0x68280000, 0xFFF80000 /* 13 */},
  { 0x68920000, 0xFFFFE000 /* 19 */},
  { 0x68928000, 0xFFFF8000 /* 17 */},
  { 0x68D00000, 0xFFF80000 /* 13 */},
  { 0x6FDD1000, 0xFFFFF000 /* 20 */},
  { 0x6FDD1000, 0xFFFFF800 /* 21 */},
  { 0x6FDD1700, 0xFFFFFF00 /* 24 */},
  { 0x6FDD4000, 0xFFFFC000 /* 18 */},
  { 0x6FDD4000, 0xFFFFF800 /* 21 */},
  { 0x6FDD4200, 0xFFFFFF00 /* 24 */},
  { 0x6FDD4500, 0xFFFFFF00 /* 24 */},
  { 0x6FDD4600, 0xFFFFFF00 /* 24 */},
  { 0x6FDD4E00, 0xFFFFFE00 /* 23 */},
  { 0x6FDD5000, 0xFFFFF000 /* 20 */},
  { 0x6FDD6000, 0xFFFFF000 /* 20 */},
  { 0x6FDD7000, 0xFFFFF800 /* 21 */},
  { 0x6FDD7800, 0xFFFFFC00 /* 22 */},
  { 0x6FDD7C00, 0xFFFFFC00 /* 22 */},
  { 0x83FD0100, 0xFFFFFF00 /* 24 */},
  { 0x83FD0500, 0xFFFFFF00 /* 24 */},
  { 0x83FD0600, 0xFFFFFF00 /* 24 */},
  { 0x83FD0800, 0xFFFFFF00 /* 24 */},
  { 0x83FD0C00, 0xFFFFFC00 /* 22 */},
  { 0x83FD1200, 0xFFFFFF00 /* 24 */},
  { 0x83FD1500, 0xFFFFFF00 /* 24 */},
  { 0x83FD1800, 0xFFFFF800 /* 21 */},
  { 0x83FD2000, 0xFFFFF000 /* 20 */},
  { 0x83FD2100, 0xFFFFFF00 /* 24 */},
  { 0x83FD2200, 0xFFFFFF00 /* 24 */},
  { 0x83FD3D00, 0xFFFFFF00 /* 24 */},
  { 0x83FD3E00, 0xFFFFFE00 /* 23 */},
  { 0x83FD8000, 0xFFFF8000 /* 17 */},
  { 0x84F50000, 0xFFFF0000 /* 16 */},
  { 0x84F59C00, 0xFFFFFC00 /* 22 */},
  { 0x84F5A000, 0xFFFFF000 /* 20 */},
  { 0x86AA0000, 0xFFFF0000 /* 16 */},
  { 0x86AA8000, 0xFFFFF800 /* 21 */},
  { 0x86AA8800, 0xFFFFF800 /* 21 */},
  { 0x86AAD900, 0xFFFFFF00 /* 24 */},
  { 0x89740000, 0xFFFE0000 /* 15 */},
  { 0x89748000, 0xFFFFE000 /* 19 */},
  { 0x8974A000, 0xFFFFF000 /* 20 */},
  { 0x89870000, 0xFFFF0000 /* 16 */},
  { 0x8A5B0000, 0xFFFF0000 /* 16 */},
  { 0x8A5B0000, 0xFFFFF000 /* 20 */},
  { 0x8A5B1000, 0xFFFFF000 /* 20 */},
  { 0x8A5B2000, 0xFFFFF000 /* 20 */},
  { 0x9D370000, 0xFFFF0000 /* 16 */},
  { 0x9D380000, 0xFFFF0000 /* 16 */},
  { 0x9D3C1700, 0xFFFFFF00 /* 24 */},
  { 0x9D3C1F00, 0xFFFFFF00 /* 24 */},
  { 0xA7DCF000, 0xFFFFFC00 /* 22 */},
  { 0xA83D0000, 0xFFFF0000 /* 16 */},
  { 0xA83E0000, 0xFFFE0000 /* 15 */},
  { 0xA83F8000, 0xFFFF8000 /* 17 */},
  { 0xBFE80000, 0xFFF80000 /* 13 */},
  { 0xC030E100, 0xFFFFFF00 /* 24 */},
  { 0xC0549F00, 0xFFFFFF00 /* 24 */},
  { 0xC054A000, 0xFFFFFE00 /* 23 */},
  { 0xC0C59D00, 0xFFFFFF00 /* 24 */},
  { 0xC1954000, 0xFFFFE000 /* 19 */},
  { 0xC1DD7100, 0xFFFFFF00 /* 24 */},
  { 0xC6310800, 0xFFFFFF00 /* 24 */},
  { 0xC6C88200, 0xFFFFFF00 /* 24 */},
  { 0xC6CEA400, 0xFFFFFF00 /* 24 */},
  { 0xC71E1000, 0xFFFFF000 /* 20 */},
  { 0xC73C1C00, 0xFFFFFF00 /* 24 */},
  { 0xC74AD200, 0xFFFFFF00 /* 24 */},
  { 0xC7675A00, 0xFFFFFE00 /* 23 */},
  { 0xC7677A00, 0xFFFFFF00 /* 24 */},
  { 0xC7F23000, 0xFFFFF800 /* 21 */},
  { 0xCA59E000, 0xFFFFF800 /* 21 */},
  { 0xCC4F8700, 0xFFFFFF00 /* 24 */},
  { 0xCC4FB300, 0xFFFFFF00 /* 24 */},
  { 0xCC4FC300, 0xFFFFFF00 /* 24 */},
  { 0xCC4FC500, 0xFFFFFF00 /* 24 */},
  { 0xCC4FFC00, 0xFFFFFF00 /* 24 */},
  { 0xCC5F6000, 0xFFFFF000 /* 20 */},
  { 0xCC988C00, 0xFFFFFE00 /* 23 */},
  { 0xCE8AA800, 0xFFFFF800 /* 21 */},
  { 0xCEBFE000, 0xFFFFE000 /* 19 */},
  { 0xCF2E0000, 0xFFFF0000 /* 16 */},
  { 0xCF2E0000, 0xFFFFE000 /* 19 */},
  { 0xCF2E2000, 0xFFFFF000 /* 20 */},
  { 0xCF2E2900, 0xFFFFFF00 /* 24 */},
  { 0xCF2E3000, 0xFFFFF000 /* 20 */},
  { 0xCF2E3A00, 0xFFFFFF00 /* 24 */},
  { 0xCF2E3E00, 0xFFFFFF00 /* 24 */},
  { 0xCF2E4000, 0xFFFFE000 /* 19 */},
  { 0xCF2E4800, 0xFFFFFF00 /* 24 */},
  { 0xCF2E4D00, 0xFFFFFF00 /* 24 */},
  { 0xCF2E6000, 0xFFFFE000 /* 19 */},
  { 0xCF2E6200, 0xFFFFFF00 /* 24 */},
  { 0xCF2E8000, 0xFFFF8000 /* 17 */},
  { 0xCF2E8000, 0xFFFFE000 /* 19 */},
  { 0xCF2EE000, 0xFFFFF000 /* 20 */},
  { 0xCF448000, 0xFFFFC000 /* 18 */},
  { 0xCF52FA00, 0xFFFFFE00 /* 23 */},
  { 0xD0448800, 0xFFFFF800 /* 21 */},
  { 0xD04C2D00, 0xFFFFFF00 /* 24 */},
  { 0xD04C2E00, 0xFFFFFF00 /* 24 */},
  { 0xD0540000, 0xFFFFFF00 /* 24 */},
  { 0xD0540100, 0xFFFFFF00 /* 24 */},
  { 0xD0540200, 0xFFFFFF00 /* 24 */},
  { 0xD0540300, 0xFFFFFF00 /* 24 */},
  { 0xD1017000, 0xFFFFFE00 /* 23 */},
  { 0xD1B98000, 0xFFFFFC00 /* 22 */},
  { 0xD1B9F000, 0xFFFFFC00 /* 22 */},
  { 0xD1F0C000, 0xFFFFE000 /* 19 */},
  { 0xD5C78000, 0xFFFFC000 /* 18 */},
  { 0xD820B400, 0xFFFFFC00 /* 22 */},
  { 0xD820F000, 0xFFFFFC00 /* 22 */},
  { 0xD820F200, 0xFFFFFF00 /* 24 */},
  { 0xD821F000, 0xFFFFFC00 /* 22 */},
  { 0, 0 }
};

u_int8_t is_skype_host(u_int32_t host) {
  /* Check if it belongs to ASN 8075 */
  int i;

  // printf("%s(%08X)\n", __FUNCTION__, host);

  for(i=0; asn8075[i].mask != 0; i++)
    if((host & asn8075[i].mask) == asn8075[i].network)
      return(1);
  
  return(0);
}

u_int8_t is_skype_flow(struct ndpi_detection_module_struct *ndpi_struct,
		       struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
	
  if(packet->iph) {
    /*
      Skype connections are identified by some SSL-like communications
      without SSL certificate being exchanged
    */	
    if(is_skype_host(ntohl(packet->iph->saddr))
       || is_skype_host(ntohl(packet->iph->daddr))) {
      return(1);
    }
  }

  return(0);
}

#if 0
static u_int is_private_addr(u_int32_t addr) {
  addr = ntohl(addr);

  if(((addr & 0xFF000000) == 0x0A000000) /* 10.0.0.0/8  */
     || ((addr & 0xFFF00000) == 0xAC100000) /* 172.16/12   */
	|| ((addr & 0xFFFF0000) == 0xC0A80000) /* 192.168/16  */
     || ((addr & 0xFF000000) == 0x7F000000) /* 127.0.0.0/8 */
     )
    return(1);
  else
    return(0);
}

static u_int64_t get_skype_key(u_int32_t src_host, u_int32_t dst_host) {
  u_int64_t key;
  
  if(src_host < dst_host) {
    key = src_host;
    key = (key << 32)+dst_host;
  } else {
    key = dst_host;
    key = (key << 32)+src_host;
  }

  return(key);
}
#endif


static void ndpi_check_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  // const u_int8_t *packet_payload = packet->payload;
  u_int32_t payload_len = packet->payload_packet_len;

#if 0
  printf("[len=%u][%02X %02X %02X %02X]\n", payload_len,
	 packet->payload[0] & 0xFF,
	 packet->payload[1] & 0xFF,
	 packet->payload[2] & 0xFF,
	 packet->payload[3] & 0xFF);
#endif

  /*
    Skype AS8220
    212.161.8.0/24
  */
  if(((ntohl(packet->iph->saddr) & 0xFFFFFF00 /* 255.255.255.0 */) == 0xD4A10800 /* 212.161.8.0 */)
     || ((ntohl(packet->iph->daddr) & 0xFFFFFF00 /* 255.255.255.0 */) == 0xD4A10800 /* 212.161.8.0 */)
     /* || is_skype_connection(ndpi_struct, packet->iph->saddr, packet->iph->daddr) */
     ) {
    ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE, NDPI_REAL_PROTOCOL);
    return;
  }

  if(packet->udp != NULL) {
    flow->l4.udp.skype_packet_id++;

    if(flow->l4.udp.skype_packet_id < 5) {
      /* skype-to-skype */
      if(((payload_len == 3) && ((packet->payload[2] & 0x0F)== 0x0d))
	 || ((payload_len >= 16)
	     && (packet->payload[0] != 0x30) /* Avoid invalid SNMP detection */
	     && (packet->payload[2] == 0x02))) {
	NDPI_LOG(NDPI_PROTOCOL_SKYPE, ndpi_struct, NDPI_LOG_DEBUG, "Found skype.\n");
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE, NDPI_REAL_PROTOCOL);
      }

      return;
    }

    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SKYPE);
    return;
  } else if(packet->tcp != NULL) {
    flow->l4.tcp.skype_packet_id++;

    if(flow->l4.tcp.skype_packet_id < 3) {
      ; /* Too early */
    } else if((flow->l4.tcp.skype_packet_id == 3)
	      /* We have seen the 3-way handshake */
	      && flow->l4.tcp.seen_syn
	      && flow->l4.tcp.seen_syn_ack
	      && flow->l4.tcp.seen_ack) {
      if((payload_len == 8) || (payload_len == 3)) {
	//printf("[SKYPE] %u/%u\n", ntohs(packet->tcp->source), ntohs(packet->tcp->dest));

	NDPI_LOG(NDPI_PROTOCOL_SKYPE, ndpi_struct, NDPI_LOG_DEBUG, "Found skype.\n");
	ndpi_int_add_connection(ndpi_struct, flow, NDPI_PROTOCOL_SKYPE, NDPI_REAL_PROTOCOL);
      }

      /* printf("[SKYPE] [id: %u][len: %d]\n", flow->l4.tcp.skype_packet_id, payload_len);  */
    } else
      NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SKYPE);

    return;
  }
}

void ndpi_search_skype(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  NDPI_LOG(NDPI_PROTOCOL_SKYPE, ndpi_struct, NDPI_LOG_DEBUG, "skype detection...\n");

  /* skip marked packets */
  if(packet->detected_protocol_stack[0] != NDPI_PROTOCOL_SKYPE)
    ndpi_check_skype(ndpi_struct, flow);
}

#endif
