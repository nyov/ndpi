/*
 * ndpi_protocols_osdpi.h
 *
 * Copyright (C) 2009-11 - ipoque GmbH
 * Copyright (C) 2011-14 - ntop.org
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


#ifndef __NDPI_API_INCLUDE_FILE__

#endif

#ifndef __NDPI_PROTOCOLS_DEFAULT_H__
#define __NDPI_PROTOCOLS_DEFAULT_H__

#ifdef __cplusplus
extern "C" {
#endif

//  #define NDPI_ENABLE_DEBUG_MESSAGES

#define NDPI_DETECTION_SUPPORT_IPV6
#define NDPI_PROTOCOL_HISTORY_SIZE				3

#define NDPI_PROTOCOL_UNKNOWN					0

#define NDPI_RESULT_IP_VRRP 				        73
#define NDPI_RESULT_IP_IPSEC					79
#define NDPI_RESULT_IP_GRE					80
#define NDPI_RESULT_IP_ICMP					81
#define NDPI_RESULT_IP_IGMP					82
#define NDPI_RESULT_IP_EGP					83
#define NDPI_RESULT_IP_SCTP					84
#define NDPI_RESULT_IP_OSPF					85
#define NDPI_RESULT_IP_IP_IN_IP					86
#define NDPI_RESULT_IP_ICMPV6					102

#define NDPI_RESULT_BASE_HTTP					7
#define NDPI_RESULT_BASE_HTTP_APPLICATION_VEOHTV 		60
#define NDPI_RESULT_BASE_SSL_NO_CERT			        64 /* SSL without certificate (Skype, Ultrasurf?) - ntop.org */
#define NDPI_RESULT_BASE_SSL					91
#define NDPI_RESULT_BASE_HTTP_APPLICATION_ACTIVESYNC		110
#define NDPI_RESULT_BASE_HTTP_CONNECT				130
#define NDPI_RESULT_BASE_HTTP_PROXY				131
#define NDPI_RESULT_BASE_SOCKS5					172 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_BASE_SOCKS4					173 /* Tomasz Bujlow <tomasz@skatnet.dk> */

#define NDPI_RESULT_APP_FTP_CONTROL				1 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_APP_MAIL_POP				2
#define NDPI_RESULT_APP_MAIL_SMTP				3
#define NDPI_RESULT_APP_MAIL_IMAP				4
#define NDPI_RESULT_APP_DNS              			5
#define NDPI_RESULT_APP_IPP					6
#define NDPI_RESULT_APP_MDNS					8
#define NDPI_RESULT_APP_NTP					9
#define NDPI_RESULT_APP_NETBIOS					10
#define NDPI_RESULT_APP_NFS					11
#define NDPI_RESULT_APP_SSDP					12
#define NDPI_RESULT_APP_BGP					13
#define NDPI_RESULT_APP_SNMP					14
#define NDPI_RESULT_APP_XDMCP					15
#define NDPI_RESULT_APP_SMB					16
#define NDPI_RESULT_APP_SYSLOG					17
#define NDPI_RESULT_APP_DHCP					18
#define NDPI_RESULT_APP_POSTGRES				19
#define NDPI_RESULT_APP_MYSQL					20
#define NDPI_RESULT_APP_TDS					21
#define NDPI_RESULT_APP_DIRECT_DOWNLOAD_LINK			22
#define NDPI_RESULT_APP_MAIL_POPS				23
#define NDPI_RESULT_APP_APPLEJUICE				24
#define NDPI_RESULT_APP_DIRECTCONNECT				25
#define NDPI_RESULT_APP_SOCRATES				26
#define NDPI_RESULT_APP_WINMX					27
#define NDPI_RESULT_APP_VMWARE					28
#define NDPI_RESULT_APP_MAIL_SMTPS				29
#define NDPI_RESULT_APP_FILETOPIA				30
#define NDPI_RESULT_APP_IMESH					31
#define NDPI_RESULT_APP_KONTIKI					32
#define NDPI_RESULT_APP_OPENFT					33
#define NDPI_RESULT_APP_FASTTRACK				34
#define NDPI_RESULT_APP_GNUTELLA				35
#define NDPI_RESULT_APP_EDONKEY					36 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_APP_BITTORRENT				37
#define NDPI_RESULT_APP_EPP					38
#define	NDPI_RESULT_APP_XBOX					47
#define	NDPI_RESULT_APP_QQ					48
#define	NDPI_RESULT_APP_MOVE					49
#define	NDPI_RESULT_APP_RTSP					50
#define NDPI_RESULT_APP_MAIL_IMAPS				51
#define NDPI_RESULT_APP_ICECAST					52
#define NDPI_RESULT_APP_PPLIVE					53 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_APP_PPSTREAM				54
#define NDPI_RESULT_APP_ZATTOO					55
#define NDPI_RESULT_APP_SHOUTCAST				56
#define NDPI_RESULT_APP_SOPCAST					57
#define NDPI_RESULT_APP_TVANTS					58
#define NDPI_RESULT_APP_TVUPLAYER				59
#define NDPI_RESULT_APP_QQLIVE					61
#define NDPI_RESULT_APP_THUNDER					62
#define NDPI_RESULT_APP_SOULSEEK				63
#define NDPI_RESULT_APP_IRC					65
#define NDPI_RESULT_APP_AYIYA					66
#define NDPI_RESULT_APP_UNENCRYPED_JABBER			67
#define NDPI_RESULT_APP_MSN					68
#define NDPI_RESULT_APP_OSCAR					69
#define NDPI_RESULT_APP_YAHOO					70
#define NDPI_RESULT_APP_BATTLEFIELD				71
#define NDPI_RESULT_APP_QUAKE					72
#define NDPI_RESULT_APP_STEAM					74 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_APP_HALFLIFE2				75
#define NDPI_RESULT_APP_WORLDOFWARCRAFT				76
#define NDPI_RESULT_APP_TELNET					77
#define NDPI_RESULT_APP_STUN					78
#define	NDPI_RESULT_APP_RTP					87
#define NDPI_RESULT_APP_RDP					88
#define NDPI_RESULT_APP_VNC					89
#define NDPI_RESULT_APP_PCANYWHERE				90
#define NDPI_RESULT_APP_SSH					92
#define NDPI_RESULT_APP_USENET					93
#define NDPI_RESULT_APP_MGCP					94
#define NDPI_RESULT_APP_IAX					95
#define NDPI_RESULT_APP_TFTP					96
#define NDPI_RESULT_APP_AFP					97
#define NDPI_RESULT_APP_STEALTHNET				98
#define NDPI_RESULT_APP_AIMINI					99
#define NDPI_RESULT_APP_SIP					100
#define NDPI_RESULT_APP_TRUPHONE				101
#define NDPI_RESULT_APP_DHCPV6					103
#define NDPI_RESULT_APP_ARMAGETRON				104
#define NDPI_RESULT_APP_CROSSFIRE				105
#define NDPI_RESULT_APP_DOFUS					106
#define NDPI_RESULT_APP_FIESTA					107
#define NDPI_RESULT_APP_FLORENSIA				108
#define NDPI_RESULT_APP_GUILDWARS				109
#define NDPI_RESULT_APP_KERBEROS				111
#define NDPI_RESULT_APP_LDAP					112
#define NDPI_RESULT_APP_MAPLESTORY				113
#define NDPI_RESULT_APP_MSSQL					114
#define NDPI_RESULT_APP_PPTP					115
#define NDPI_RESULT_APP_WARCRAFT3				116
#define NDPI_RESULT_APP_WORLD_OF_KUNG_FU			117
#define NDPI_RESULT_APP_MEEBO					118
#define NDPI_RESULT_APP_DROPBOX					121
#define NDPI_RESULT_APP_SKYPE					125
#define NDPI_RESULT_APP_DCERPC					127
#define NDPI_RESULT_APP_NETFLOW					128
#define NDPI_RESULT_APP_SFLOW					129
#define NDPI_RESULT_APP_CITRIX					132
#define NDPI_RESULT_APP_SKYFILE_PREPAID				136
#define NDPI_RESULT_APP_SKYFILE_RUDICS				137
#define NDPI_RESULT_APP_SKYFILE_POSTPAID			138
#define NDPI_RESULT_APP_CITRIX_ONLINE				139
#define NDPI_RESULT_APP_WEBEX					141
#define NDPI_RESULT_APP_VIBER					144
#define NDPI_RESULT_APP_RADIUS					146
#define NDPI_RESULT_APP_WINDOWS_UPDATE				147 /* Thierry Laurion */
#define NDPI_RESULT_APP_TEAMVIEWER				148 /* xplico.org */
#define NDPI_RESULT_APP_LOTUS_NOTES				150
#define NDPI_RESULT_APP_SAP					151
#define NDPI_RESULT_APP_GTP					152
#define NDPI_RESULT_APP_UPNP					153
#define NDPI_RESULT_APP_LLMNR					154
#define NDPI_RESULT_APP_REMOTE_SCAN				155
#define NDPI_RESULT_APP_SPOTIFY					156
#define NDPI_RESULT_APP_H323					158 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_OPENVPN					159 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_NOE					160 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_CISCOVPN				161 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_TEAMSPEAK				162 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_TOR					163 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_SKINNY					164 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_RTCP					165 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_RSYNC					166 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_ORACLE					167 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_CORBA					168 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_UBUNTUONE				169 /* Remy Mudingay <mudingay@ill.fr> */
#define NDPI_RESULT_APP_WHOIS_DAS				170
#define NDPI_RESULT_APP_COLLECTD				171
#define NDPI_RESULT_APP_RTMP					174 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_APP_FTP_DATA				175 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_APP_PANDO					185 /* Tomasz Bujlow <tomasz@skatnet.dk> */

#define NDPI_RESULT_CONTENT_AVI					39
#define NDPI_RESULT_CONTENT_FLASH				40
#define NDPI_RESULT_CONTENT_OGG					41
#define	NDPI_RESULT_CONTENT_MPEG				42
#define	NDPI_RESULT_CONTENT_QUICKTIME				43
#define	NDPI_RESULT_CONTENT_REALMEDIA				44
#define	NDPI_RESULT_CONTENT_WINDOWSMEDIA			45
#define	NDPI_RESULT_CONTENT_MMS					46
#define NDPI_RESULT_CONTENT_WEBM				157

#define NDPI_RESULT_SERVICE_FACEBOOK				119
#define NDPI_RESULT_SERVICE_TWITTER				120
#define NDPI_RESULT_SERVICE_GMAIL				122
#define NDPI_RESULT_SERVICE_GOOGLE_MAPS				123
#define NDPI_RESULT_SERVICE_YOUTUBE				124
#define NDPI_RESULT_SERVICE_GOOGLE				126
#define NDPI_RESULT_SERVICE_NETFLIX				133
#define NDPI_RESULT_SERVICE_LASTFM				134
#define NDPI_RESULT_SERVICE_GROOVESHARK				135
#define NDPI_RESULT_SERVICE_APPLE				140
#define NDPI_RESULT_SERVICE_WHATSAPP				142
#define NDPI_RESULT_SERVICE_APPLE_ICLOUD			143
#define NDPI_RESULT_SERVICE_APPLE_ITUNES			145
#define NDPI_RESULT_SERVICE_TUENTI				149
#define NDPI_RESULT_SERVICE_WIKIPEDIA				176 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_SERVICE_MSN					177 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_SERVICE_AMAZON				178 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_SERVICE_EBAY				179 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_SERVICE_CNN					180 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_SERVICE_DROPBOX				181 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_SERVICE_SKYPE				182 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_SERVICE_VIBER				183 /* Tomasz Bujlow <tomasz@skatnet.dk> */
#define NDPI_RESULT_SERVICE_YAHOO				184 /* Tomasz Bujlow <tomasz@skatnet.dk> */

/* UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE UPDATE */
#define NDPI_LAST_IMPLEMENTED_PROTOCOL				185

#define NDPI_MAX_SUPPORTED_PROTOCOLS (NDPI_LAST_IMPLEMENTED_PROTOCOL + 1)
#define NDPI_MAX_NUM_CUSTOM_PROTOCOLS                           (NDPI_NUM_BITS-NDPI_LAST_IMPLEMENTED_PROTOCOL)
#ifdef __cplusplus
}
#endif
#endif
