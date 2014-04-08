/*
 * ip_protocols.c
 *
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
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


#include "ndpi_protocols.h"

void ndpi_search_ip_protocols(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if (packet->iph == NULL) {
#ifdef NDPI_DETECTION_SUPPORT_IPV6
    if (packet->iphv6 == NULL)
#endif
      return;
  }

  switch (packet->l4_protocol) {
  case 1:
    flow->ndpi_result_ip = NDPI_RESULT_IP_ICMP;
    break;
  case 2:
    flow->ndpi_result_ip = NDPI_RESULT_IP_IGMP;
    break;
  case 4:
    flow->ndpi_result_ip = NDPI_RESULT_IP_IP_IN_IP;
    break;    
  case 6:
    flow->ndpi_result_ip = NDPI_RESULT_IP_TCP;
    break;
  case 8:
    flow->ndpi_result_ip = NDPI_RESULT_IP_EGP;
    break;
  case 17:
    flow->ndpi_result_ip = NDPI_RESULT_IP_UDP;
    break;    
  case 47:
    flow->ndpi_result_ip = NDPI_RESULT_IP_GRE;
    break;
  case 50:
  case 51:
    flow->ndpi_result_ip = NDPI_RESULT_IP_IPSEC;
    break;
  case 58:
    flow->ndpi_result_ip = NDPI_RESULT_IP_ICMPV6;
    break;    
  case 89:
    flow->ndpi_result_ip = NDPI_RESULT_IP_OSPF;
    break;
  case 112:
    flow->ndpi_result_ip = NDPI_RESULT_IP_VRRP;
    break;
  case 132:
    flow->ndpi_result_ip = NDPI_RESULT_IP_SCTP;
    break;
  default:
    flow->ndpi_result_ip = NDPI_RESULT_IP_UNKNOWN;
    break;
  }
}

void ndpi_register_ip_protocols (struct ndpi_detection_module_struct *ndpi_mod) {
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_ICMP, "ICMP", ndpi_search_ip_protocols);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_IGMP, "IGMP", NULL);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_IP_IN_IP, "IP_in_IP", NULL);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_TCP, "TCP", NULL);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_EGP, "EGP", NULL);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_UDP, "UDP", NULL);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_GRE, "GRE", NULL);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_IPSEC, "IPSec", NULL);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_ICMPV6, "ICMPv6", NULL);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_OSPF, "OSPF", NULL);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_VRRP, "VRRP", NULL);
  ndpi_initialize_scanner_ip (ndpi_mod, NDPI_RESULT_IP_SCTP, "SCTP", NULL);
}
