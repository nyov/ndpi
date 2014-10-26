/*
 * ndpi_protocol_ids.h
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

#ifndef __NDPI_PROTOCOLS_DEFAULT_H__
#define __NDPI_PROTOCOLS_DEFAULT_H__

#define NDPI_DETECTION_SUPPORT_IPV6


/* This level is for different IP protocols, see: http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers. */
typedef enum {
  NDPI_RESULT_IP_STILL_UNKNOWN,
  NDPI_RESULT_IP_UNKNOWN,
  NDPI_RESULT_IP_TCP, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_IP_UDP, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_IP_VRRP,
  NDPI_RESULT_IP_IPSEC,
  NDPI_RESULT_IP_GRE,
  NDPI_RESULT_IP_ICMP,
  NDPI_RESULT_IP_IGMP,
  NDPI_RESULT_IP_EGP,
  NDPI_RESULT_IP_SCTP,
  NDPI_RESULT_IP_OSPF,
  NDPI_RESULT_IP_IP_IN_IP,
  NDPI_RESULT_IP_ICMPV6,
  NDPI_RESULT_IP_LAST
} ndpi_result_ip_t;

/* This level is for protocols, which:
 * - hide inside some stuff, which is covered from being exploited (as all tunnels, VPNS)
 * - are base for other protocols or applications (as HTTP, above which many other or applications are built)
 * Basically, obtaining a result on this level (without obtaining anything on higher levels) means that the
 * real traffic is hidden from being seen.
 */
typedef enum {
  NDPI_RESULT_BASE_STILL_UNKNOWN,
  NDPI_RESULT_BASE_UNKNOWN,
  NDPI_RESULT_BASE_HTTP,
  NDPI_RESULT_BASE_HTTP_CONNECT,
  NDPI_RESULT_BASE_HTTP_PROXY,
  NDPI_RESULT_BASE_SSL,
  NDPI_RESULT_BASE_SSL_NO_CERT, /* SSL without certificate (Skype, Ultrasurf?) - ntop.org */
  NDPI_RESULT_BASE_SOCKS4, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_BASE_SOCKS5, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_BASE_CISCOVPN, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_BASE_OPENVPN, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_BASE_TOR, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_BASE_LAST
} ndpi_result_base_t;

typedef enum {
  NDPI_RESULT_APP_STILL_UNKNOWN,
  NDPI_RESULT_APP_UNKNOWN,
  NDPI_RESULT_APP_FTP_CONTROL, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_APP_POP,
  NDPI_RESULT_APP_SMTP,
  NDPI_RESULT_APP_IMAP,
  NDPI_RESULT_APP_DNS,
  NDPI_RESULT_APP_IPP,
  NDPI_RESULT_APP_MDNS,
  NDPI_RESULT_APP_NTP,
  NDPI_RESULT_APP_NETBIOS,
  NDPI_RESULT_APP_NFS,
  NDPI_RESULT_APP_SSDP,
  NDPI_RESULT_APP_BGP,
  NDPI_RESULT_APP_SNMP,
  NDPI_RESULT_APP_XDMCP,
  NDPI_RESULT_APP_SMB,
  NDPI_RESULT_APP_SYSLOG,
  NDPI_RESULT_APP_DHCP,
  NDPI_RESULT_APP_POSTGRES,
  NDPI_RESULT_APP_MYSQL,
  NDPI_RESULT_APP_TDS,
  NDPI_RESULT_APP_DIRECT_DOWNLOAD,
  NDPI_RESULT_APP_POPS,
  NDPI_RESULT_APP_APPLEJUICE,
  NDPI_RESULT_APP_DIRECTCONNECT,
  NDPI_RESULT_APP_SOCRATES,
  NDPI_RESULT_APP_WINMX,
  NDPI_RESULT_APP_VMWARE,
  NDPI_RESULT_APP_SMTPS,
  NDPI_RESULT_APP_FILETOPIA,
  NDPI_RESULT_APP_IMESH,
  NDPI_RESULT_APP_KONTIKI,
  NDPI_RESULT_APP_OPENFT,
  NDPI_RESULT_APP_FASTTRACK,
  NDPI_RESULT_APP_GNUTELLA,
  NDPI_RESULT_APP_EDONKEY, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_APP_BITTORRENT,
  NDPI_RESULT_APP_EPP,
  NDPI_RESULT_APP_XBOX,
  NDPI_RESULT_APP_QQ,
  NDPI_RESULT_APP_RTSP,
  NDPI_RESULT_APP_IMAPS,
  NDPI_RESULT_APP_ICECAST,
  NDPI_RESULT_APP_PPLIVE, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_APP_PPSTREAM,
  NDPI_RESULT_APP_ZATTOO,
  NDPI_RESULT_APP_SHOUTCAST,
  NDPI_RESULT_APP_SOPCAST,
  NDPI_RESULT_APP_TVANTS,
  NDPI_RESULT_APP_TVUPLAYER,
  NDPI_RESULT_APP_VEOHTV,
  NDPI_RESULT_APP_QQLIVE,
  NDPI_RESULT_APP_THUNDER,
  NDPI_RESULT_APP_SOULSEEK,
  NDPI_RESULT_APP_IRC,
  NDPI_RESULT_APP_AYIYA,
  NDPI_RESULT_APP_UNENCRYPED_JABBER,
  NDPI_RESULT_APP_MSN,
  NDPI_RESULT_APP_OSCAR,
  NDPI_RESULT_APP_YAHOO_MESSENGER,
  NDPI_RESULT_APP_BATTLEFIELD,
  NDPI_RESULT_APP_QUAKE,
  NDPI_RESULT_APP_STEAM, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_APP_HALFLIFE2,
  NDPI_RESULT_APP_WORLDOFWARCRAFT,
  NDPI_RESULT_APP_TELNET,
  NDPI_RESULT_APP_STUN,
  NDPI_RESULT_APP_RTP,
  NDPI_RESULT_APP_RDP,
  NDPI_RESULT_APP_VNC,
  NDPI_RESULT_APP_PCANYWHERE,
  NDPI_RESULT_APP_SSH,
  NDPI_RESULT_APP_USENET,
  NDPI_RESULT_APP_MGCP,
  NDPI_RESULT_APP_IAX,
  NDPI_RESULT_APP_TFTP,
  NDPI_RESULT_APP_AFP,
  NDPI_RESULT_APP_STEALTHNET,
  NDPI_RESULT_APP_AIMINI,
  NDPI_RESULT_APP_SIP,
  NDPI_RESULT_APP_DHCPV6,
  NDPI_RESULT_APP_ARMAGETRON,
  NDPI_RESULT_APP_CROSSFIRE,
  NDPI_RESULT_APP_DOFUS,
  NDPI_RESULT_APP_FIESTA,
  NDPI_RESULT_APP_FLORENSIA,
  NDPI_RESULT_APP_GUILDWARS,
  NDPI_RESULT_APP_ACTIVESYNC,
  NDPI_RESULT_APP_KERBEROS,
  NDPI_RESULT_APP_LDAP,
  NDPI_RESULT_APP_MAPLESTORY,
  NDPI_RESULT_APP_MSSQL,
  NDPI_RESULT_APP_PPTP,
  NDPI_RESULT_APP_WARCRAFT3,
  NDPI_RESULT_APP_WORLD_OF_KUNG_FU,
  NDPI_RESULT_APP_MEEBO,
  NDPI_RESULT_APP_DROPBOX,
  NDPI_RESULT_APP_DCERPC,
  NDPI_RESULT_APP_NETFLOW,
  NDPI_RESULT_APP_SFLOW,
  NDPI_RESULT_APP_CITRIX,
  NDPI_RESULT_APP_SKYFILE_PREPAID,
  NDPI_RESULT_APP_SKYFILE_RUDICS,
  NDPI_RESULT_APP_SKYFILE_POSTPAID,
  NDPI_RESULT_APP_VIBER,
  NDPI_RESULT_APP_RADIUS,
  NDPI_RESULT_APP_WINDOWS_UPDATE, /* Thierry Laurion */
  NDPI_RESULT_APP_TEAMVIEWER, /* xplico.org */
  NDPI_RESULT_APP_LOTUS_NOTES,
  NDPI_RESULT_APP_SAP,
  NDPI_RESULT_APP_GTP,
  NDPI_RESULT_APP_UPNP,
  NDPI_RESULT_APP_LLMNR,
  NDPI_RESULT_APP_REMOTE_SCAN,
  NDPI_RESULT_APP_SPOTIFY,
  NDPI_RESULT_APP_H323, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_APP_NOE, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_APP_TEAMSPEAK, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_APP_SKINNY, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_APP_RTCP, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_APP_RSYNC, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_APP_ORACLE, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_APP_CORBA, /* Remy Mudingay <mudingay@ill.fr> */
  NDPI_RESULT_APP_WHOIS_DAS,
  NDPI_RESULT_APP_COLLECTD,
  NDPI_RESULT_APP_RTMP, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_APP_FTP_DATA, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_APP_PANDO, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_APP_SKYPE,
  NDPI_RESULT_APP_MEGACO, /* Gianluca Costa <g.costa@xplico.org> */
  NDPI_RESULT_APP_REDIS,
  NDPI_RESULT_APP_ZMQ,
  NDPI_RESULT_APP_VHUA,
  NDPI_RESULT_APP_LAST
} ndpi_result_app_t;

typedef enum {
  NDPI_RESULT_CONTENT_STILL_UNKNOWN,
  NDPI_RESULT_CONTENT_UNKNOWN,
  NDPI_RESULT_CONTENT_AVI,
  NDPI_RESULT_CONTENT_FLASH,
  NDPI_RESULT_CONTENT_OGG,
  NDPI_RESULT_CONTENT_MPEG,
  NDPI_RESULT_CONTENT_QUICKTIME,
  NDPI_RESULT_CONTENT_REALMEDIA,
  NDPI_RESULT_CONTENT_WINDOWSMEDIA,
  NDPI_RESULT_CONTENT_WEBM,
  NDPI_RESULT_CONTENT_EXE,
  NDPI_RESULT_CONTENT_ZIP,
  NDPI_RESULT_CONTENT_RAR,
  NDPI_RESULT_CONTENT_EBML,
  NDPI_RESULT_CONTENT_JPG,
  NDPI_RESULT_CONTENT_GIF,
  NDPI_RESULT_CONTENT_PHP,
  NDPI_RESULT_CONTENT_UNIX_SCRIPT,
  NDPI_RESULT_CONTENT_PDF,
  NDPI_RESULT_CONTENT_PNG,
  NDPI_RESULT_CONTENT_HTML,
  NDPI_RESULT_CONTENT_7ZIP,
  NDPI_RESULT_CONTENT_GZIP,
  NDPI_RESULT_CONTENT_XML,
  NDPI_RESULT_CONTENT_FLAC,
  NDPI_RESULT_CONTENT_MP3,
  NDPI_RESULT_CONTENT_RPM,
  NDPI_RESULT_CONTENT_WZ_PATCH,
  NDPI_RESULT_CONTENT_BKF,
  NDPI_RESULT_CONTENT_DOC,
  NDPI_RESULT_CONTENT_ASP,
  NDPI_RESULT_CONTENT_WMS,
  NDPI_RESULT_CONTENT_DEB,
  NDPI_RESULT_CONTENT_SPF,
  NDPI_RESULT_CONTENT_ABIF,
  NDPI_RESULT_CONTENT_BZIP2,
  NDPI_RESULT_CONTENT_LAST
} ndpi_result_content_t;

typedef enum {
  NDPI_RESULT_SERVICE_STILL_UNKNOWN,
  NDPI_RESULT_SERVICE_UNKNOWN,
  NDPI_RESULT_SERVICE_FACEBOOK,
  NDPI_RESULT_SERVICE_TWITTER,
  NDPI_RESULT_SERVICE_YOUTUBE,
  NDPI_RESULT_SERVICE_GOOGLE,
  NDPI_RESULT_SERVICE_NETFLIX,
  NDPI_RESULT_SERVICE_LASTFM,
  NDPI_RESULT_SERVICE_GROOVESHARK,
  NDPI_RESULT_SERVICE_APPLE,
  NDPI_RESULT_SERVICE_WHATSAPP,
  NDPI_RESULT_SERVICE_APPLE_ICLOUD,
  NDPI_RESULT_SERVICE_APPLE_ITUNES,
  NDPI_RESULT_SERVICE_TUENTI,
  NDPI_RESULT_SERVICE_WIKIPEDIA, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_SERVICE_MSN, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_SERVICE_AMAZON, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_SERVICE_EBAY, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_SERVICE_CNN, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_SERVICE_DROPBOX, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_SERVICE_SKYPE, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_SERVICE_VIBER, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_SERVICE_YAHOO, /* Tomasz Bujlow <tomasz@skatnet.dk> */
  NDPI_RESULT_SERVICE_LAST
} ndpi_result_service_t;

#endif
