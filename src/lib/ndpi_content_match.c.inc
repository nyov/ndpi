/*
 * ndpi_content_match.c
 *
 * Copyright (C) 2011-15 - ntop.org
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

typedef struct {
  char *string_to_match, *proto_name;
  int protocol_id;
  ndpi_protocol_breed_t protocol_breed;
} ndpi_protocol_match;

/* ****************************************************** */

/*
  Host-based match

  HTTP:  Server: field
  HTTPS: Server certificate name
 */

ndpi_protocol_match host_match[] = {
  { "amazon.com",			"Amazon",		NDPI_SERVICE_AMAZON, NDPI_PROTOCOL_ACCEPTABLE },
  { "amazonaws.com",			"Amazon",		NDPI_SERVICE_AMAZON, NDPI_PROTOCOL_ACCEPTABLE },
  { "amazon-adsystem.com",		"Amazon",		NDPI_SERVICE_AMAZON, NDPI_PROTOCOL_ACCEPTABLE },
  { ".apple.com",			"Apple",		NDPI_SERVICE_APPLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".mzstatic.com",			"Apple",		NDPI_SERVICE_APPLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".icloud.com",			"AppleiCloud",		NDPI_SERVICE_APPLE_ICLOUD, NDPI_PROTOCOL_ACCEPTABLE },
  { "itunes.apple.com",			"AppleiTunes",		NDPI_SERVICE_APPLE_ITUNES, NDPI_PROTOCOL_FUN },
  { ".cnn.c",				"CNN",			NDPI_SERVICE_CNN, NDPI_PROTOCOL_FUN },
  { ".cnn.net",				"CNN",			NDPI_SERVICE_CNN, NDPI_PROTOCOL_FUN },
  { ".dropbox.com",			"DropBox",		NDPI_SERVICE_DROPBOX, NDPI_PROTOCOL_SAFE },
  { ".ebay.com",			"eBay",			NDPI_SERVICE_EBAY, NDPI_PROTOCOL_ACCEPTABLE },
  { ".ebaystatic.com",			"eBay",			NDPI_SERVICE_EBAY, NDPI_PROTOCOL_ACCEPTABLE },
  { ".ebaydesc.com",			"eBay",			NDPI_SERVICE_EBAY, NDPI_PROTOCOL_ACCEPTABLE },
  { ".ebayrtm.com",			"eBay",			NDPI_SERVICE_EBAY, NDPI_PROTOCOL_ACCEPTABLE },
  { ".facebook.com",			"Facebook",		NDPI_SERVICE_FACEBOOK, NDPI_PROTOCOL_FUN },
  { ".fbcdn.net",			"Facebook",		NDPI_SERVICE_FACEBOOK, NDPI_PROTOCOL_FUN },
  { "fbcdn-",				"Facebook",		NDPI_SERVICE_FACEBOOK, NDPI_PROTOCOL_FUN },  /* fbcdn-video-a-akamaihd.net */
  { ".gstatic.com",			"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".googlesyndication.com",		"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".googletagservices.com",		"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".2mdn.net",			"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".doubleclick.net",			"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE }, /* Ads */
  { "googleads.",			"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "google-analytics.",		"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "googleusercontent.",		"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "googleadservices.",		"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "googleapis.com",	   	        "Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { "maps.google.",			"GoogleMaps",		NDPI_SERVICE_GOOGLE_MAPS, NDPI_PROTOCOL_ACCEPTABLE },
  { "maps.gstatic.com",			"GoogleMaps",		NDPI_SERVICE_GOOGLE_MAPS, NDPI_PROTOCOL_ACCEPTABLE },
  { ".gmail.",				"GMail",		NDPI_SERVICE_GMAIL, NDPI_PROTOCOL_SAFE },
  { "mail.google.",			"GMail",		NDPI_SERVICE_GMAIL, NDPI_PROTOCOL_SAFE },
  { ".grooveshark.com",			"GrooveShark",		NDPI_SERVICE_GROOVESHARK, NDPI_PROTOCOL_FUN },
  { ".last.fm",				"LastFM",		NDPI_SERVICE_LASTFM, NDPI_PROTOCOL_FUN },
  { "msn.com",				"MSN",			NDPI_SERVICE_MSN, NDPI_PROTOCOL_FUN },
  { ".netflix.com",			"NetFlix",		NDPI_SERVICE_NETFLIX, NDPI_PROTOCOL_FUN },
  { ".skype.",				"Skype",		NDPI_SERVICE_SKYPE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".skypeassets.",			"Skype",		NDPI_SERVICE_SKYPE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".skypedata.",			"Skype",		NDPI_SERVICE_SKYPE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".skypeecs-", /* no final . */	"Skype",		NDPI_SERVICE_SKYPE, NDPI_PROTOCOL_ACCEPTABLE },
  { ".tuenti.com",			"Tuenti",		NDPI_SERVICE_TUENTI, NDPI_PROTOCOL_ACCEPTABLE },
  { ".twttr.com",			"Twitter",		NDPI_SERVICE_TWITTER, NDPI_PROTOCOL_ACCEPTABLE },
  { "twitter.",				"Twitter",		NDPI_SERVICE_TWITTER, NDPI_PROTOCOL_ACCEPTABLE },
  { "twimg.com",			"Twitter",		NDPI_SERVICE_TWITTER, NDPI_PROTOCOL_ACCEPTABLE },
  { ".viber.com",			"Viber",		NDPI_SERVICE_VIBER, NDPI_PROTOCOL_ACCEPTABLE },
  { "wikipedia.",			"Wikipedia",		NDPI_SERVICE_WIKIPEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { "wikimedia.",			"Wikipedia",		NDPI_SERVICE_WIKIPEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { "mediawiki.",			"Wikipedia",		NDPI_SERVICE_WIKIPEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { "wikimediafoundation.",		"Wikipedia",		NDPI_SERVICE_WIKIPEDIA, NDPI_PROTOCOL_ACCEPTABLE },
  { ".whatsapp.net",			"WhatsApp",		NDPI_SERVICE_WHATSAPP, NDPI_PROTOCOL_ACCEPTABLE },
  { ".yahoo.",				"Yahoo",		NDPI_SERVICE_YAHOO, NDPI_PROTOCOL_ACCEPTABLE },
  { "yimg.com",				"Yahoo",		NDPI_SERVICE_YAHOO, NDPI_PROTOCOL_ACCEPTABLE },
  { "yahooapis.",			"Yahoo",		NDPI_SERVICE_YAHOO, NDPI_PROTOCOL_ACCEPTABLE },
  { "youtube.",				"YouTube",		NDPI_SERVICE_YOUTUBE, NDPI_PROTOCOL_FUN },
  { ".googlevideo.com",			"YouTube",		NDPI_SERVICE_YOUTUBE, NDPI_PROTOCOL_FUN },
  { ".ytimg.com",			"YouTube",		NDPI_SERVICE_YOUTUBE, NDPI_PROTOCOL_FUN },
  { "youtube-nocookie.",		"YouTube",		NDPI_SERVICE_YOUTUBE, NDPI_PROTOCOL_FUN },
  { ".google.",				"Google",		NDPI_SERVICE_GOOGLE, NDPI_PROTOCOL_ACCEPTABLE },
  { NULL, 0 }
};


/*
  Mime-type content match match
*/
ndpi_protocol_match content_match[] = {
  { "audio/mpeg",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "audio/x-mpeg",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "audio/mpeg3",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "audio/mp4a",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "video/mpeg",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "video/nsv",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "misc/ultravox",			NULL,		        NDPI_CONTENT_MPEG, NDPI_PROTOCOL_FUN },
  { "audio/ogg",			NULL,		        NDPI_CONTENT_OGG, NDPI_PROTOCOL_FUN },
  { "video/ogg",			NULL,		        NDPI_CONTENT_OGG, NDPI_PROTOCOL_FUN },
  { "application/ogg",			NULL,		        NDPI_CONTENT_OGG, NDPI_PROTOCOL_FUN },
  { "video/flv",			NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "video/x-flv",			NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "application/x-fcs",		NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "application/x-shockwave-flash",	NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_ACCEPTABLE },
  { "video/flash",			NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "application/flv",			NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "flv-application/octet-stream",	NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "application/futuresplash",		NULL,		        NDPI_CONTENT_FLASH, NDPI_PROTOCOL_FUN },
  { "video/quicktime",			NULL,		        NDPI_CONTENT_QUICKTIME, NDPI_PROTOCOL_FUN },
  { "video/mp4",			NULL,		        NDPI_CONTENT_QUICKTIME, NDPI_PROTOCOL_FUN },
  { "video/x-m4v",			NULL,		        NDPI_CONTENT_QUICKTIME, NDPI_PROTOCOL_FUN },
  { "audio/x-pn-realaudio",		NULL,		        NDPI_CONTENT_REALMEDIA, NDPI_PROTOCOL_FUN },
  { "application/vnd.rn-realmedia",	NULL,		        NDPI_CONTENT_REALMEDIA, NDPI_PROTOCOL_FUN },
  { "video/x-ms-",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "asf",			        NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "asx",			        NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "video/x-msvideo",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "audio/x-wav",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "application/vnd.ms.wms-hdr.asfv1",	NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "NSPlayer/",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA, NDPI_PROTOCOL_FUN },
  { "application/x-mms-framed",		NULL,		        NDPI_CONTENT_MMS, NDPI_PROTOCOL_FUN },
  { "Xbox Live Client/",		NULL,		        NDPI_PROTOCOL_XBOX, NDPI_PROTOCOL_FUN },
  { "Windows-Update-Agent",		NULL,		        NDPI_PROTOCOL_WINDOWS_UPDATE, NDPI_PROTOCOL_FUN },
  { "audio/webm",			NULL,		        NDPI_CONTENT_WEBM, NDPI_PROTOCOL_FUN },
  { "video/webm",			NULL,		        NDPI_CONTENT_WEBM, NDPI_PROTOCOL_FUN },
  { "application/x-rtsp-tunnelled",	NULL,		        NDPI_PROTOCOL_RTSP, NDPI_PROTOCOL_FUN },
  { NULL, 0 }
};
