/*
 * proto_openvpn.c
 *
 * Copyright (C) 2013 Remy Mudingay <mudingay@ill.fr>
 *
 */



#include "ndpi_utils.h"
#include "ndpi_protocols.h"

void ndpi_search_openvpn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t dport = 0, sport = 0;
  
  if(packet->udp != NULL) {    
    sport = ntohs(packet->udp->source), dport = ntohs(packet->udp->dest);
    if ((packet->payload_packet_len >= 25) && (sport == 443 || dport == 443) &&
	(packet->payload[0] == 0x17 && packet->payload[1] == 0x01 &&
	 packet->payload[2] == 0x00 && packet->payload[3] == 0x00)) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found openvpn udp 443.\n");
      flow->ndpi_result_base = NDPI_RESULT_BASE_OPENVPN;
      flow->ndpi_excluded_base[NDPI_RESULT_BASE_OPENVPN] = 1;
      return;
    }
    
    if ((packet->payload_packet_len >= 40) &&
	(sport == 1194 || dport == 1194) &&
	  (packet->payload[0] == 0x30 || packet->payload[0] == 0x31 || packet->payload[0] == 0x32 || packet->payload[0] == 0x33 || packet->payload[0] == 0x34 ||
	   packet->payload[0] == 0x35 || packet->payload[0] == 0x36 || packet->payload[0] == 0x37 || packet->payload[0] == 0x38 || packet->payload[0] == 0x39))	{
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found openvpn broadcast udp STD.\n");
      flow->ndpi_result_base = NDPI_RESULT_BASE_OPENVPN;
      flow->ndpi_excluded_base[NDPI_RESULT_BASE_OPENVPN] = 1;
      return;
    }
  }
  
  flow->ndpi_excluded_base[NDPI_RESULT_BASE_OPENVPN] = 1;
}

void ndpi_register_proto_openvpn (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {1194, 0, 0, 0, 0};
  int udp_ports[5] = {1194, 0, 0, 0, 0};

  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_BASE_OPENVPN, "OpenVPN", NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_openvpn);
}
