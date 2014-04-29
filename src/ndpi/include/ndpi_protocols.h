/*
 * ndpi_protocols.h
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
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


#ifndef __NDPI_PROTOCOLS_INCLUDE_FILE__
#define __NDPI_PROTOCOLS_INCLUDE_FILE__

#include "ndpi_main.h"

/* the get_uXX will return raw network packet bytes !! */
#define get_u_int8_t(X,O)  (*(u_int8_t *)(((u_int8_t *)X) + O))
#define get_u_int16_t(X,O)  (*(u_int16_t *)(((u_int8_t *)X) + O))
#define get_u_int32_t(X,O)  (*(u_int32_t *)(((u_int8_t *)X) + O))
#define get_u_int64_t(X,O)  (*(u_int64_t *)(((u_int8_t *)X) + O))

/* new definitions to get little endian from network bytes */
#define get_ul8(X,O) get_u_int8_t(X,O)


#if defined(__LITTLE_ENDIAN__)
#define get_l16(X,O)  get_u_int16_t(X,O)
#define get_l32(X,O)  get_u_int32_t(X,O)
#elif defined(__BIG_ENDIAN__)
/* convert the bytes from big to little endian */
#ifndef __KERNEL__
# define get_l16(X,O) bswap_16(get_u_int16_t(X,O))
# define get_l32(X,O) bswap_32(get_u_int32_t(X,O))
#else
# define get_l16(X,O) __cpu_to_le16(get_u_int16_t(X,O))
# define get_l32(X,O) __cpu_to_le32(get_u_int32_t(X,O))
#endif

#else

#error "__BYTE_ORDER MUST BE DEFINED !"

#endif							/* __BYTE_ORDER */

/* define memory callback function */
#define match_first_bytes(payload,st) (memcmp((payload),(st),(sizeof(st)-1))==0)

void ndpi_register_ip_protocols (struct ndpi_detection_module_struct *mod);

void ndpi_register_proto_ciscovpn (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_http (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_openvpn (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_socks4 (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_socks5 (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ssl (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_tor (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_bittorrent (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_dns (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_imap (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_pop (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_smtp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ssl_based (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_edonkey (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ftp_control (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ftp_data (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_netbios (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ntp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_pando (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_pplive (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_rdp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_rtmp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_skype (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_smb (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_sopcast (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ssh (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_steam (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_dropbox (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ppstream (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_spotify (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_various_directdownloadlink (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_world_of_warcraft (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_bgp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_dhcp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_dhcpv6 (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_directconnect (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_fasttrack (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_gnutella (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_imesh (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_netflow (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_nfs (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_rtp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_sip (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_snmp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_teamviewer (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_telnet (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_tftp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_usenet (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_vmware (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_vnc (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_warcraft3 (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_yahoo_messenger (struct ndpi_detection_module_struct *mod);

void ndpi_register_content_raw (struct ndpi_detection_module_struct *mod);

void ndpi_register_content_http (struct ndpi_detection_module_struct *mod);
void ndpi_unregister_content_http (struct ndpi_detection_module_struct *mod);

void ndpi_register_service_parser (struct ndpi_detection_module_struct *mod);
void ndpi_unregister_service_parser (struct ndpi_detection_module_struct *mod);

#endif /* __NDPI_PROTOCOLS_INCLUDE_FILE__ */
