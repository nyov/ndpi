/*
 * cdn_parser.c
 *
 * Copyright (C) 2014 Tomasz Bujlow <tomasz@bujlow.com>
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

#include "ndpi_api.h"
#include "ahocorasick.h"

static void ndpi_match_cdn(struct ndpi_detection_module_struct *ndpi_struct, ndpi_automa *automa, struct ndpi_flow_struct *flow,
						char *string_to_match, u_int string_to_match_len) {
  
  int matching_protocol_id = NDPI_RESULT_CDN_STILL_UNKNOWN;
  struct ndpi_packet_struct *packet = &flow->packet;
  AC_TEXT_t ac_input_text;

  if ((automa->ac_automa == NULL) || (string_to_match_len == 0)) {
    return;
  }

  if (!automa->ac_automa_finalized) {
    ac_automata_finalize((AC_AUTOMATA_t*)automa->ac_automa);
    automa->ac_automa_finalized = 1;
  }

  ac_input_text.astring = string_to_match, ac_input_text.length = string_to_match_len;
  ac_automata_search (((AC_AUTOMATA_t*)automa->ac_automa), &ac_input_text, (void*)&matching_protocol_id);
  ac_automata_reset(((AC_AUTOMATA_t*)automa->ac_automa));

  if (matching_protocol_id != NDPI_RESULT_CDN_STILL_UNKNOWN) {
    flow->ndpi_result_cdn = matching_protocol_id;
    flow->ndpi_excluded_cdn = 1;
  }
}

void ndpi_search_cdn_by_ip(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow, u_int32_t saddr, u_int32_t daddr) { /* host endianess */
  
    /*
      Apple (FaceTime, iMessage,...)
      17.0.0.0/8
    */
    if(((saddr & 0xFF000000 /* 255.0.0.0 */) == 0x11000000 /* 17.0.0.0 */)
       || ((daddr & 0xFF000000 /* 255.0.0.0 */) == 0x11000000 /* 17.0.0.0 */)) {
      flow->ndpi_result_cdn = NDPI_RESULT_CDN_APPLE;
      return;
    }

    /* 
       Skype
       157.56.0.0/14, 157.60.0.0/16, 157.54.0.0/15
    */
    if(
       (((saddr & 0xFF3F0000 /* 255.63.0.0 */) == 0x9D380000 /* 157.56.0.0/ */) || ((daddr & 0xFF3F0000 /* 255.63.0.0 */) == 0x9D380000))
       || (((saddr & 0xFFFF0000 /* 255.255.0.0 */) == 0x9D3C0000 /* 157.60.0.0/ */) || ((daddr & 0xFFFF0000 /* 255.255.0.0 */) == 0x9D3D0000))
       || (((saddr & 0xFF7F0000 /* 255.255.0.0 */) == 0x9D360000 /* 157.54.0.0/ */) || ((daddr & 0xFF7F0000 /* 255.127.0.0 */) == 0x9D360000))
       || (((saddr & 0xFFFE0000 /* 255.254.0.0 */) == 0x9D360000 /* 157.54.0.0/ */) || ((daddr & 0xFFFE0000 /* 255.254.0.0 */) == 0x9D360000))
       ) {
      flow->ndpi_result_cdn = NDPI_RESULT_CDN_SKYPE;
      return;
    }
  
    /*
      Google
      173.194.0.0/16
    */
    if(((saddr & 0xFFFF0000 /* 255.255.0.0 */) == 0xADC20000  /* 173.194.0.0 */)
       || ((daddr & 0xFFFF0000 /* 255.255.0.0 */) ==0xADC20000 /* 173.194.0.0 */)) {
      flow->ndpi_result_cdn = NDPI_RESULT_CDN_GOOGLE;
      return;
    }
    
    /* 
       Twitter Inc.
    */
    
    if (ndpi_ips_match(saddr, daddr, 0xC0854C00, 22)     /* 192.133.76.0/22 */
      || ndpi_ips_match(saddr, daddr, 0xC7109C00, 22)  /* 199.16.156.0/22 */
      || ndpi_ips_match(saddr, daddr, 0xC73B9400, 22)  /* 199.59.148.0/22 */
      || ndpi_ips_match(saddr, daddr, 0xC7603A00, 23)  /* 199.96.58.0/23  */
      || ndpi_ips_match(saddr, daddr, 0xC7603E00, 23)  /* 199.96.62.0/23  */
    ) {
      flow->ndpi_result_cdn = NDPI_RESULT_CDN_TWITTER;
      return;
    }
    
    /* 
       CIDR:           69.53.224.0/19
       OriginAS:       AS2906
       NetName:        NETFLIX-INC
    */
    if(((saddr & 0xFFFFE000 /* 255.255.224.0 */) == 0x4535E000 /* 69.53.224.0 */)
       || ((daddr & 0xFFFFE000 /* 255.255.224.0 */) == 0x4535E000 /* 69.53.224.0 */)) {
      flow->ndpi_result_cdn = NDPI_RESULT_CDN_NETFLIX;
      return;
    }    
}

void ndpi_search_cdn(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  
  if (flow->ndpi_excluded_cdn == 1) {
    return;
  }
  
  if (flow->server_certificate != NULL && strlen(flow->server_certificate) != 0) {
    ndpi_match_cdn(ndpi_struct, &ndpi_struct->cdn_automa, flow, flow->server_certificate, strlen(flow->server_certificate));
  }
  
  if (flow->ndpi_excluded_cdn == 1) {
    return;
  }
  
  if (flow->client_certificate != NULL && strlen(flow->client_certificate) != 0) {
    ndpi_match_cdn(ndpi_struct, &ndpi_struct->cdn_automa, flow, flow->client_certificate, strlen(flow->client_certificate));
  }
  
  if (flow->ndpi_excluded_cdn == 1) {
    return;
  }
  
  /* Do not excluded the cdn based on the IP header detection! */
  if (packet->iph /* IPv4 Only: we need to support packet->iphv6 at some point. */) {
    ndpi_search_cdn_by_ip(ndpi_struct, flow, ntohl(packet->iph->saddr), ntohl(packet->iph->daddr));
  }
  
  /* Exclude the cdn and break after 20 packets. */
  if (flow->packet_counter > 20) { 
    flow->ndpi_excluded_cdn = 1;
    
    if (flow->ndpi_result_cdn == NDPI_RESULT_CDN_STILL_UNKNOWN) {
      NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Could not find any cdn.\n");
      flow->ndpi_result_cdn = NDPI_RESULT_CDN_UNKNOWN;
    }
    
    return;
  }
}

static int ac_match_cdn_handler(AC_MATCH_t *m, void *param) {
  
  int *matching_protocol_id = (int*)param;

  /* Stopping to the first match. We might consider searching
   * for the more specific match, paying more cpu cycles. */
  *matching_protocol_id = m->patterns[0].rep.number;

  return 1; /* 0 to continue searching, !0 to stop */
}

static int cdn_to_automa(struct ndpi_detection_module_struct *ndpi_struct, ndpi_automa *automa, char *value, int protocol_id) {
  AC_PATTERN_t ac_pattern;
  ac_pattern.astring = value;
  ac_pattern.rep.number = protocol_id;
  ac_pattern.length = strlen(ac_pattern.astring);
  ac_automata_add(((AC_AUTOMATA_t*)automa->ac_automa), &ac_pattern);
}

void ndpi_register_cdn_parser (struct ndpi_detection_module_struct *ndpi_mod) {
  
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_FACEBOOK, "Facebook", ndpi_search_cdn);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_TWITTER, "Twitter", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_YOUTUBE, "YouTube", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_GOOGLE, "Google", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_NETFLIX, "Netflix", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_LASTFM, "LastFM", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_GROOVESHARK, "Grooveshark", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_APPLE, "Apple", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_WHATSAPP, "WhatsApp", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_APPLE_ICLOUD, "Apple_iCloud", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_APPLE_ITUNES, "Apple_iTunes", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_TUENTI, "Tuenti", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_WIKIPEDIA, "Wikipedia", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_MSN, "MSN", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_AMAZON, "Amazon", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_EBAY, "eBay", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_CNN, "CNN", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_DROPBOX, "Dropbox", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_SKYPE, "Skype", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_VIBER, "Viber", NULL);
  ndpi_initialize_scanner_cdn (ndpi_mod, NDPI_RESULT_CDN_YAHOO, "Yahoo", NULL);
  
  ndpi_mod->cdn_automa.ac_automa = ac_automata_init(ac_match_cdn_handler);
  
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "amazon.com", NDPI_RESULT_CDN_AMAZON);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "amazonaws.com", NDPI_RESULT_CDN_AMAZON);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "amazon-adsystem.com", NDPI_RESULT_CDN_AMAZON);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".apple.com", NDPI_RESULT_CDN_APPLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".mzstatic.com", NDPI_RESULT_CDN_APPLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".icloud.com", NDPI_RESULT_CDN_APPLE_ICLOUD);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "itunes.apple.com", NDPI_RESULT_CDN_APPLE_ITUNES);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".cnn.c", NDPI_RESULT_CDN_CNN);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".cnn.net", NDPI_RESULT_CDN_CNN);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".dropbox.com", NDPI_RESULT_CDN_DROPBOX);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".ebay.com", NDPI_RESULT_CDN_EBAY);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".ebaystatic.com", NDPI_RESULT_CDN_EBAY);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".ebaydesc.com", NDPI_RESULT_CDN_EBAY);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".ebayrtm.com", NDPI_RESULT_CDN_EBAY);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".facebook.com", NDPI_RESULT_CDN_FACEBOOK);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".fbcdn.net", NDPI_RESULT_CDN_FACEBOOK);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "fbcdn-", NDPI_RESULT_CDN_FACEBOOK);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".gstatic.com", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".googlesyndication.com", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".googletagcdns.com", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".2mdn.net", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".doubleclick.net", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "googleads.", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "google-analytics.", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "googleusercontent.", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "googleadcdns.", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "googleapis.com", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".google.", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".gmail.", NDPI_RESULT_CDN_GOOGLE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".grooveshark.com", NDPI_RESULT_CDN_GROOVESHARK);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".last.fm", NDPI_RESULT_CDN_LASTFM);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "msn.com", NDPI_RESULT_CDN_MSN);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".netflix.com", NDPI_RESULT_CDN_NETFLIX);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".skype.com", NDPI_RESULT_CDN_SKYPE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".skypeassets.com", NDPI_RESULT_CDN_SKYPE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".tuenti.com", NDPI_RESULT_CDN_TUENTI);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".twttr.com", NDPI_RESULT_CDN_TWITTER);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "twitter.", NDPI_RESULT_CDN_TWITTER);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "twimg.com", NDPI_RESULT_CDN_TWITTER);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".viber.com", NDPI_RESULT_CDN_VIBER);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "wikipedia.", NDPI_RESULT_CDN_WIKIPEDIA);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "wikimedia.", NDPI_RESULT_CDN_WIKIPEDIA);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "mediawiki.", NDPI_RESULT_CDN_WIKIPEDIA);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "wikimediafoundation.", NDPI_RESULT_CDN_WIKIPEDIA);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".whatsapp.net", NDPI_RESULT_CDN_WHATSAPP);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".yahoo.", NDPI_RESULT_CDN_YAHOO);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "yimg.com", NDPI_RESULT_CDN_YAHOO);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "yahooapis.", NDPI_RESULT_CDN_YAHOO);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "youtube.", NDPI_RESULT_CDN_YOUTUBE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".googlevideo.com", NDPI_RESULT_CDN_YOUTUBE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, ".ytimg.com", NDPI_RESULT_CDN_YOUTUBE);
  cdn_to_automa(ndpi_mod, &ndpi_mod->cdn_automa, "youtube-nocookie.", NDPI_RESULT_CDN_YOUTUBE);
}

void ndpi_unregister_cdn_parser (struct ndpi_detection_module_struct *ndpi_mod) {
  
  if(ndpi_mod->cdn_automa.ac_automa != NULL) {
      ac_automata_release((AC_AUTOMATA_t*)ndpi_mod->cdn_automa.ac_automa);
  }
}
