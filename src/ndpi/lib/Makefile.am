lib_LTLIBRARIES = libndpi.la

noinst_HEADERS = ../include/ndpi_main.h \
		../include/ndpi_protocols.h \
		../include/ndpi_structs.h \
		../include/ndpi_utils.h \
		../include/linux_compat.h


# this will create a library 1.4.0
LIB_AC=1
LIB_REV=4
LIB_ANC=0

# ntop
AM_CFLAGS=-fPIC @PLATFORM_DEPENDENT@

libndpi_la_CPPFLAGS = -I$(top_srcdir)/src/ndpi/include/  -I$(top_srcdir)/src/ahocorasick/include/
libndpi_la_LDFLAGS=-version-info ${LIB_AC}:${LIB_REV}:${LIB_ANC}

libndpi_la_SOURCES = \
			../../ahocorasick/src/ahocorasick.c \
			../../ahocorasick/src/node.c \
			../../ahocorasick/src/sort.c \
			ndpi_main.c \
			scanners/ip_protocols.c \
			scanners/proto_ciscovpn.c \
			scanners/proto_http.c \
			scanners/proto_openvpn.c \
			scanners/proto_socks4.c \
			scanners/proto_socks5.c \
			scanners/proto_ssl.c \
			scanners/proto_tor.c \
			scanners/proto_bittorrent.c \
			scanners/proto_dns.c \
			scanners/proto_imap.c \
			scanners/proto_pop.c \
			scanners/proto_smtp.c \
			scanners/proto_ssl_based.c \
			scanners/proto_edonkey.c \
			scanners/proto_ftp_control.c \
			scanners/proto_ftp_data.c \
			scanners/proto_netbios.c \
			scanners/proto_ntp.c \
			scanners/proto_pando.c \
			scanners/proto_pplive.c \
			scanners/proto_rdp.c \
			scanners/proto_rtmp.c \
			scanners/proto_skype.c \
			scanners/proto_smb.c \
			scanners/proto_sopcast.c \
			scanners/proto_ssh.c \
			scanners/proto_steam.c \
			scanners/proto_dropbox.c \
			scanners/proto_ppstream.c \
			scanners/proto_spotify.c \
			scanners/proto_various_directdownloadlink.c \
			scanners/proto_world_of_warcraft.c \
			scanners/content_raw.c \
			scanners/content_http.c \
			scanners/service_parser.c \
			scanners/proto_bgp.c \
			scanners/proto_dhcp.c \
			scanners/proto_dhcpv6.c \
			scanners/proto_directconnect.c \
			scanners/proto_fasttrack.c \
			scanners/proto_gnutella.c \
			scanners/proto_imesh.c \
			scanners/proto_netflow.c \
			scanners/proto_nfs.c \
			scanners/proto_rtp.c \
			scanners/proto_sip.c \
			scanners/proto_snmp.c \
			scanners/proto_teamviewer.c \
			scanners/proto_telnet.c \
			scanners/proto_tftp.c \
			scanners/proto_usenet.c \
			scanners/proto_vmware.c \
			scanners/proto_vnc.c \
			scanners/proto_warcraft3.c \
			scanners/proto_yahoo_messenger.c
