/*
 * content_http.c
 *
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

#include "ndpi_utils.h"
#include "ahocorasick.h"

static void ndpi_match_content_subprotocol(struct ndpi_detection_module_struct *ndpi_struct, ndpi_automa *automa, struct ndpi_flow_struct *flow,
						char *string_to_match, u_int string_to_match_len) {
  
  int matching_protocol_id = NDPI_RESULT_CONTENT_STILL_UNKNOWN;
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

  if (matching_protocol_id != NDPI_RESULT_CONTENT_STILL_UNKNOWN) {
    flow->ndpi_result_content = matching_protocol_id;
  }
}

static void flash_check_http_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
  const u_int8_t *pos;

  if (packet->empty_line_position_set == 0 || (packet->empty_line_position + 10) > (packet->payload_packet_len))
    return;

  pos = &packet->payload[packet->empty_line_position] + 2;


  if (memcmp(pos, "FLV", 3) == 0 && pos[3] == 0x01 && (pos[4] == 0x01 || pos[4] == 0x04 || pos[4] == 0x05)
      && pos[5] == 0x00 && pos[6] == 0x00 && pos[7] == 0x00 && pos[8] == 0x09) {

    flow->ndpi_result_content = NDPI_RESULT_CONTENT_FLASH;
  }
}


static void avi_check_http_payload(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;

  if (packet->empty_line_position_set == 0 && flow->l4.tcp.http_empty_line_seen == 0)
    return;

  if (packet->empty_line_position_set != 0 && ((packet->empty_line_position + 20) > (packet->payload_packet_len))
      && flow->l4.tcp.http_empty_line_seen == 0) {
    flow->l4.tcp.http_empty_line_seen = 1;
    return;
  }

  if (flow->l4.tcp.http_empty_line_seen == 1) {
    if (packet->payload_packet_len > 20 && memcmp(packet->payload, "RIFF", 4) == 0
	&& memcmp(packet->payload + 8, "AVI LIST", 8) == 0) {
      flow->ndpi_result_content = NDPI_RESULT_CONTENT_AVI;
    }
    flow->l4.tcp.http_empty_line_seen = 0;
    return;
  }

  if (packet->empty_line_position_set != 0) {
    // check for avi header
    // for reference see http://msdn.microsoft.com/archive/default.asp?url=/archive/en-us/directx9_c/directx/htm/avirifffilereference.asp
    u_int32_t p = packet->empty_line_position + 2;

    if ((p + 16) <= packet->payload_packet_len && memcmp(&packet->payload[p], "RIFF", 4) == 0
	&& memcmp(&packet->payload[p + 8], "AVI LIST", 8) == 0) {
      flow->ndpi_result_content = NDPI_RESULT_CONTENT_AVI;
    }
  }
}

void ndpi_search_http_content(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
  struct ndpi_packet_struct *packet = &flow->packet;
  
  if (flow->ndpi_result_content != NDPI_RESULT_CONTENT_STILL_UNKNOWN) {
    return;
  }

  if (packet->content_line.ptr != NULL && packet->content_line.len != 0) {
    ndpi_match_content_subprotocol(ndpi_struct, &ndpi_struct->http_content_automa, flow, (char*)packet->content_line.ptr, packet->content_line.len);
  }
  
  if (flow->ndpi_result_content != NDPI_RESULT_CONTENT_STILL_UNKNOWN) {
    return;
  }  
  
  if (packet->user_agent_line.ptr != NULL && packet->user_agent_line.len != 0) {
    ndpi_match_content_subprotocol(ndpi_struct, &ndpi_struct->http_content_automa, flow, (char*)packet->user_agent_line.ptr, packet->user_agent_line.len);
  }
  
  if (flow->ndpi_result_content != NDPI_RESULT_CONTENT_STILL_UNKNOWN) {
    return;
  }  
  
  if (packet->host_line.ptr != NULL && packet->host_line.len != 0) {
    ndpi_match_content_subprotocol(ndpi_struct, &ndpi_struct->http_content_automa, flow, (char*)packet->host_line.ptr, packet->host_line.len);
  }
  
  if (flow->ndpi_result_content != NDPI_RESULT_CONTENT_STILL_UNKNOWN) {
    return;
  }
  
  if ((flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP)
    || (flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP_CONNECT)
    || (flow->ndpi_result_base == NDPI_RESULT_BASE_HTTP_PROXY)) {
    
    flash_check_http_payload(ndpi_struct, flow);
  
    if (flow->ndpi_result_content != NDPI_RESULT_CONTENT_STILL_UNKNOWN) {
      return;
    }
    
    avi_check_http_payload(ndpi_struct, flow);
  } 
	
  /* Break after 10 packets. */
  if ((flow->ndpi_result_content == NDPI_RESULT_CONTENT_STILL_UNKNOWN) && (flow->packet_counter > 20)) {
    NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Could not find any HTTP content.\n");
    flow->ndpi_result_content = NDPI_RESULT_CONTENT_UNKNOWN;
    return;
  }
}

static int ac_match_http_content_handler(AC_MATCH_t *m, void *param) {
  
  int *matching_protocol_id = (int*)param;

  /* Stopping to the first match. We might consider searching
   * for the more specific match, paying more cpu cycles. */
  *matching_protocol_id = m->patterns[0].rep.number;

  return 1; /* 0 to continue searching, !0 to stop */
}

static int http_content_to_automa(struct ndpi_detection_module_struct *ndpi_struct, ndpi_automa *automa, char *value, int protocol_id) {
  AC_PATTERN_t ac_pattern;
  ac_pattern.astring = value;
  ac_pattern.rep.number = protocol_id;
  ac_pattern.length = strlen(ac_pattern.astring);
  ac_automata_add(((AC_AUTOMATA_t*)automa->ac_automa), &ac_pattern);
}

void ndpi_register_content_http (struct ndpi_detection_module_struct *ndpi_mod) {
  
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_MPEG, "MPEG", ndpi_search_http_content);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_OGG, "OGG", NULL);
  /*ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_AVI, "AVI", NULL); Do not register now as we erase the function from raw content registration!) */
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_FLASH, "Flash_Video", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_QUICKTIME, "QuickTime_Video", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_REALMEDIA, "Real_Media", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_WINDOWSMEDIA, "Windows_Media", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_WEBM, "WebM", NULL);
  
  ndpi_mod->http_content_automa.ac_automa = ac_automata_init(ac_match_http_content_handler);
  
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "audio/mpeg", NDPI_RESULT_CONTENT_MPEG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "audio/x-mpeg", NDPI_RESULT_CONTENT_MPEG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "audio/mpeg3", NDPI_RESULT_CONTENT_MPEG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "audio/mp4a", NDPI_RESULT_CONTENT_MPEG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/mp4", NDPI_RESULT_CONTENT_MPEG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/mpeg", NDPI_RESULT_CONTENT_MPEG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/nsv", NDPI_RESULT_CONTENT_MPEG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "misc/ultravox", NDPI_RESULT_CONTENT_MPEG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "audio/ogg", NDPI_RESULT_CONTENT_OGG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/ogg", NDPI_RESULT_CONTENT_OGG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "application/ogg", NDPI_RESULT_CONTENT_OGG);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/flv", NDPI_RESULT_CONTENT_FLASH);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/x-flv", NDPI_RESULT_CONTENT_FLASH);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "application/x-fcs", NDPI_RESULT_CONTENT_FLASH);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "application/x-shockwave-flash", NDPI_RESULT_CONTENT_FLASH);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/flash", NDPI_RESULT_CONTENT_FLASH);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "application/flv", NDPI_RESULT_CONTENT_FLASH);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "flv-application/octet-stream", NDPI_RESULT_CONTENT_FLASH);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "application/futuresplash", NDPI_RESULT_CONTENT_FLASH);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/quicktime", NDPI_RESULT_CONTENT_QUICKTIME);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/x-m4v", NDPI_RESULT_CONTENT_QUICKTIME);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "audio/x-pn-realaudio", NDPI_RESULT_CONTENT_REALMEDIA);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "application/vnd.rn-realmedia", NDPI_RESULT_CONTENT_REALMEDIA);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/x-ms-", NDPI_RESULT_CONTENT_WINDOWSMEDIA);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "asf", NDPI_RESULT_CONTENT_WINDOWSMEDIA);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "asx", NDPI_RESULT_CONTENT_WINDOWSMEDIA);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/x-msvideo", NDPI_RESULT_CONTENT_WINDOWSMEDIA);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "audio/x-wav", NDPI_RESULT_CONTENT_WINDOWSMEDIA);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "application/vnd.ms.wms-hdr.asfv1", NDPI_RESULT_CONTENT_WINDOWSMEDIA);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "NSPlayer/", NDPI_RESULT_CONTENT_WINDOWSMEDIA);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "audio/webm", NDPI_RESULT_CONTENT_WEBM);
  http_content_to_automa(ndpi_mod, &ndpi_mod->http_content_automa, "video/webm", NDPI_RESULT_CONTENT_WEBM);
}

void ndpi_unregister_content_http (struct ndpi_detection_module_struct *ndpi_mod) {
  
  if(ndpi_mod->http_content_automa.ac_automa != NULL) {
      ac_automata_release((AC_AUTOMATA_t*)ndpi_mod->http_content_automa.ac_automa);
  }
}
