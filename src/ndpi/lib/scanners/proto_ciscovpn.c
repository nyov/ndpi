/*
 * proto_ciscovpn.c
 * Copyright (C) 2013 by Remy Mudingay <mudingay@ill.fr>
 *
 */


#include "ndpi_protocols.h"

void ndpi_search_ciscovpn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  u_int16_t udport = 0, usport = 0;
  u_int16_t tdport = 0, tsport = 0;


  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "search CISCOVPN.\n");

  if(packet->tcp != NULL) {
    tsport = ntohs(packet->tcp->source), tdport = ntohs(packet->tcp->dest);
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "calculated CISCOVPN over tcp ports.\n");
  }
  if(packet->udp != NULL) {
    usport = ntohs(packet->udp->source), udport = ntohs(packet->udp->dest);
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "calculated CISCOVPN over udp ports.\n");
  }

  if((tdport == 10000 && tsport == 10000) ||
     ((tsport == 443 || tdport == 443) &&
      (packet->payload[0] == 0x17 &&
       packet->payload[1] == 0x01 &&
       packet->payload[2] == 0x00 &&
       packet->payload[3] == 0x00)
      )
     )

    {
      /* This is a good query  17010000*/
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found CISCOVPN.\n");
      flow->ndpi_result_base = NDPI_RESULT_BASE_CISCOVPN;
      flow->ndpi_excluded_base[NDPI_RESULT_BASE_CISCOVPN] = 1;
    } 
  else if(
	  (
	   (usport == 10000 && udport == 10000)
	   &&
	   (packet->payload[0] == 0xfe &&
	    packet->payload[1] == 0x57 &&
	    packet->payload[2] == 0x7e &&
	    packet->payload[3] == 0x2b)
	   )
	  )
    {


      /* This is a good query  fe577e2b */
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found CISCOVPN.\n");
      flow->ndpi_result_base = NDPI_RESULT_BASE_CISCOVPN;
      flow->ndpi_excluded_base[NDPI_RESULT_BASE_CISCOVPN] = 1;
    } else {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "exclude CISCOVPN.\n");
    flow->ndpi_excluded_base[NDPI_RESULT_BASE_CISCOVPN] = 1;
  }

}

void ndpi_register_proto_ciscovpn (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {10000, 0, 0, 0, 0};
  int udp_ports[5] = {10000, 0, 0, 0, 0};

  ndpi_initialize_scanner_base (ndpi_mod, NDPI_RESULT_BASE_CISCOVPN, "Cisco_VPN", NDPI_SELECTION_BITMASK_PROTOCOL_TCP_OR_UDP_WITH_PAYLOAD, tcp_ports, udp_ports, ndpi_search_ciscovpn);
}
