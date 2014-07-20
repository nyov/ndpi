/*
 * ndpi_protocols.h
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
void ndpi_register_proto_megaco (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_redis (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_zmq (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_afp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_applejuice (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ayiya (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_collectd (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_corba (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_dcerpc (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_gtp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_guildwars (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_h323 (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_halflife2_and_mods (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_http_activesync (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_kerberos (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_kontiki (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_mssql (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_mysql (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_noe (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_openft (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_oracle (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_pcanywhere (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_pptp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_radius (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_rsync (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_rtcp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_rtsp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_sflow (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ssdp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_stealthnet (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_tds (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_viber (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_whoisdas (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_world_of_kung_fu (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_xdmcp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_aimini (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_armagetron (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_battlefield (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_citrix (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_crossfire (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_dofus (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_fiesta (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_filetopia (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_florensia (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_iax (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_icecast (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ipp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_irc (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_jabber (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_ldap (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_lotus_notes (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_maplestory (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_mdns (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_meebo (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_mgcp (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_msn (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_oscar (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_postgres (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_qq (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_quake (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_shoutcast (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_skinny (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_socrates (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_soulseek (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_stun (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_syslog (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_teamspeak (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_thunder (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_tvants (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_tvuplayer (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_veohtv (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_winmx (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_xbox (struct ndpi_detection_module_struct *mod);
void ndpi_register_proto_zattoo (struct ndpi_detection_module_struct *mod);

void ndpi_register_content_raw (struct ndpi_detection_module_struct *mod);

void ndpi_register_content_http (struct ndpi_detection_module_struct *mod);
void ndpi_unregister_content_http (struct ndpi_detection_module_struct *mod);

void ndpi_register_service_parser (struct ndpi_detection_module_struct *mod);
void ndpi_unregister_service_parser (struct ndpi_detection_module_struct *mod);

#endif /* __NDPI_PROTOCOLS_INCLUDE_FILE__ */
