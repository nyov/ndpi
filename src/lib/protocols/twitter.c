/*
 * twitter.c
 *
 * Copyright (C) 2014 - ntop.org
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

#ifdef NDPI_SERVICE_TWITTER

static void ndpi_int_twitter_add_connection(struct ndpi_detection_module_struct
                                             *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_int_add_connection(ndpi_struct, flow, NDPI_SERVICE_TWITTER, NDPI_REAL_PROTOCOL);
}

void ndpi_search_twitter(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{

  /*
    Twitter AS34702

    http://bgp.he.net/AS13414
  */
  if(flow->packet.iph) {
    // IPv4
    u_int32_t src = ntohl(flow->packet.iph->saddr);
    u_int32_t dst = ntohl(flow->packet.iph->daddr);

    // 192.133.76.0/22
    /* 192.133.76.0 - 192.133.79.255 */
    if(((src >= 3229961216) && (src <= 3229962239))
       || ((dst >= 3229961216) && (dst <= 3229962239))
       || ((src & 0xFFFFFC00 /* 255.255.252.0  */) == 0x5C854C00/* 92.133.76.0 */)
       || ((dst & 0xFFFFFC00 /* 255.255.252.0  */) == 0x5C854C00/* 92.133.76.0 */)
       ) {
      ndpi_int_twitter_add_connection(ndpi_struct, flow);
      return;
    }
    // 199.16.156.0/22
    /* 199.16.156.0 - 199.16.159.255 */
    if(((src >= 3339754496) && (src <= 3339755519))
       || ((dst >= 3339754496) && (dst <= 3339755519))
       || ((src & 0xFFFFFC00 /* 255.255.252.0  */) == 0xC7109C00/* 199.16.156.0 */)
       || ((dst & 0xFFFFFC00 /* 255.255.252.0  */) == 0xC7109C00/* 199.16.156.0 */)
       ) {
      ndpi_int_twitter_add_connection(ndpi_struct, flow);
      return;
    }

     // 199.59.148.0/22
    /* 199.59.148.0 - 199.59.151.255 */
    if(((src >= 3342570496) && (src <= 3342571519))
       || ((dst >= 3342570496) && (dst <= 3342571519))
       || ((src & 0xFFFFFC00 /* 255.255.252.0  */) == 0xC73B9400/* 199.59.148.0 */)
       || ((dst & 0xFFFFFC00 /* 255.255.252.0  */) == 0xC73B9400/* 199.59.148.0 */)
       ) {
      ndpi_int_twitter_add_connection(ndpi_struct, flow);
      return;
    }

     // 199.96.56.0 /21
    /* 199.96.56.0 - 199.96.63.255 */
    if(((src >= 3344971776) && (src <= 3344973823))
       || ((dst >= 3344971776) && (dst <= 3344973823))
       || ((src & 0xFFFFF800 /* 255.255.248.0  */) == 0xC7603800/* 199.96.56.0 */)
       || ((dst & 0xFFFFF800 /* 255.255.248.0  */) == 0xC7603800/* 199.96.56.0 */)
       ) {
      ndpi_int_twitter_add_connection(ndpi_struct, flow);
      return;
    }

  }

  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_SERVICE_TWITTER);
}
#endif
