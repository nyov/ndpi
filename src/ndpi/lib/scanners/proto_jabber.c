/*
 * proto_jabber.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@skatnet.dk>
 *
 * This file is part of nDPIng, an open source deep packet inspection
 * library based on nDPI, OpenDPI, and PACE technology by ipoque GmbH
 *
 * nDPIng is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPIng is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPIng.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */

#include "ndpi_protocols.h"
#include "ndpi_utils.h"

static void check_content_type_and_change_protocol(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int16_t x) {
  
  struct ndpi_packet_struct *packet = &flow->packet;

  if (packet->payload_packet_len > x + 18 && packet->payload_packet_len > x && packet->payload_packet_len > 18) {
    const u_int16_t lastlen = packet->payload_packet_len - 18;
    for (x = 0; x < lastlen; x++) {
      if (memcmp(&packet->payload[x], "=\"im.truphone.com\"", 18) == 0 ||
	  memcmp(&packet->payload[x], "='im.truphone.com'", 18) == 0) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "changed to TRUPHONE.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_UNENCRYPED_JABBER;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_UNENCRYPED_JABBER] = 1;
      }
    }
  }

  return;
}

void ndpi_search_jabber(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  struct ndpi_id_struct *src = flow->src;
  struct ndpi_id_struct *dst = flow->dst;

  u_int16_t x;

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "JABBER detection.\n");

  /* search for jabber file transfer */
  /* this part is working asymmetrically */
  if (packet->tcp != NULL && packet->tcp->syn != 0 && packet->payload_packet_len == 0) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "check jabber syn\n");
    
    if (src != NULL && src->jabber_file_transfer_port[0] != 0) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
	       "src jabber ft port set, ports are: %u, %u\n", ntohs(src->jabber_file_transfer_port[0]),
	       ntohs(src->jabber_file_transfer_port[1]));
      if (((u_int32_t)
	   (packet->tick_timestamp - src->jabber_stun_or_ft_ts)) >= ndpi_struct->jabber_file_transfer_timeout) {
	NDPI_LOG(0, ndpi_struct,
		 NDPI_LOG_DEBUG, "JABBER src stun timeout %u %u\n", src->jabber_stun_or_ft_ts,
		 packet->tick_timestamp);
	src->jabber_file_transfer_port[0] = 0;
	src->jabber_file_transfer_port[1] = 0;
      } else if (src->jabber_file_transfer_port[0] == packet->tcp->dest
		 || src->jabber_file_transfer_port[0] == packet->tcp->source
		 || src->jabber_file_transfer_port[1] == packet->tcp->dest
		 || src->jabber_file_transfer_port[1] == packet->tcp->source) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found jabber file transfer.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_UNENCRYPED_JABBER;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_UNENCRYPED_JABBER] = 1;
      }
    }
    
    if (dst != NULL && dst->jabber_file_transfer_port[0] != 0) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG,
	       "dst jabber ft port set, ports are: %u, %u\n", ntohs(dst->jabber_file_transfer_port[0]),
	       ntohs(dst->jabber_file_transfer_port[1]));
      if (((u_int32_t)
	   (packet->tick_timestamp - dst->jabber_stun_or_ft_ts)) >= ndpi_struct->jabber_file_transfer_timeout) {
	NDPI_LOG(0, ndpi_struct,
		 NDPI_LOG_DEBUG, "JABBER dst stun timeout %u %u\n", dst->jabber_stun_or_ft_ts,
		 packet->tick_timestamp);
	dst->jabber_file_transfer_port[0] = 0;
	dst->jabber_file_transfer_port[1] = 0;
      } else if (dst->jabber_file_transfer_port[0] == packet->tcp->dest
		 || dst->jabber_file_transfer_port[0] == packet->tcp->source
		 || dst->jabber_file_transfer_port[1] == packet->tcp->dest
		 || dst->jabber_file_transfer_port[1] == packet->tcp->source) {
	NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "found jabber file transfer.\n");
	flow->ndpi_result_app = NDPI_RESULT_APP_UNENCRYPED_JABBER;
	flow->ndpi_excluded_app[NDPI_RESULT_APP_UNENCRYPED_JABBER] = 1;
      }
    }
    
    return;
  }

  if (packet->tcp != 0 && packet->payload_packet_len == 0) {
    return;
  }

  /* search for jabber here */
  /* this part is working asymmetrically */
  if ((packet->payload_packet_len > 13 && memcmp(packet->payload, "<?xml version=", 14) == 0)
      || (packet->payload_packet_len >= NDPI_STATICSTRING_LEN("<stream:stream ")
	  && memcmp(packet->payload, "<stream:stream ", NDPI_STATICSTRING_LEN("<stream:stream ")) == 0)) {

    if (packet->payload_packet_len > 47) {
      const u_int16_t lastlen = packet->payload_packet_len - 47;
      for (x = 0; x < lastlen; x++) {
	if (memcmp
	    (&packet->payload[x],
	     "xmlns:stream='http://etherx.jabber.org/streams'", 47) == 0
	    || memcmp(&packet->payload[x], "xmlns:stream=\"http://etherx.jabber.org/streams\"", 47) == 0) {
	  NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "found JABBER.\n");
	  x += 47;
	  flow->ndpi_result_app = NDPI_RESULT_APP_UNENCRYPED_JABBER;
	  flow->ndpi_excluded_app[NDPI_RESULT_APP_UNENCRYPED_JABBER] = 1;

	  /* search for other protocols: Truphone */
	  check_content_type_and_change_protocol(ndpi_struct, flow, x);
	  return;
	}
      }
    }
  }
  
  if (flow->packet_counter < 3) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_TRACE, "packet_counter: %u\n", flow->packet_counter);
    return;
  }

  NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "JABBER Excluded\n");
  flow->ndpi_excluded_app[NDPI_RESULT_APP_UNENCRYPED_JABBER] = 1;
  flow->ndpi_excluded_app[NDPI_RESULT_APP_TRUPHONE] = 1;
}

void ndpi_register_proto_jabber (struct ndpi_detection_module_struct *ndpi_mod) {

  int tcp_ports[5] = {0, 0, 0, 0, 0};
  int udp_ports[5] = {0, 0, 0, 0, 0};

  ndpi_initialize_scanner_app (ndpi_mod, NDPI_RESULT_APP_UNENCRYPED_JABBER, "Unencryped_Jabber", NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_OR_UDP_WITHOUT_RETRANSMISSION, tcp_ports, udp_ports, ndpi_search_jabber);
}
