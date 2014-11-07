/*
 * content_raw.c
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

void ndpi_search_raw_content(struct ndpi_detection_module_struct *ndpi_struct, struct ndpi_flow_struct *flow) {
	struct ndpi_packet_struct *packet = &flow->packet;

	if (packet->payload_packet_len < 4) {
		return;
	}

	/* RIFF is a meta-format for storing AVI and WAV files */
	if (match_first_bytes(packet->payload, "RIFF")) {
		flow->ndpi_result_content = NDPI_RESULT_CONTENT_AVI;
		return;
	}

	/* MZ is a .exe file */
	if ((packet->payload[0] == 'M') && (packet->payload[1] == 'Z') && (packet->payload[3] == 0x00)) {
		flow->ndpi_result_content = NDPI_RESULT_CONTENT_EXE;
		return;
	}

	/* Ogg files */
	if (match_first_bytes(packet->payload, "OggS")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_OGG;
		return;
	}

	/* ZIP files */
	if ((packet->payload[0] == 'P') && (packet->payload[1] == 'K') && (packet->payload[2] == 0x03) && (packet->payload[3] == 0x04)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_ZIP;
		return;
	}

	/* MPEG files */
	if ((packet->payload[0] == 0x00) && (packet->payload[1] == 0x00) && (packet->payload[2] == 0x01) && (packet->payload[3] == 0xba)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_MPEG;
		return;
	}

	/* RAR files */
	if (match_first_bytes(packet->payload, "Rar!")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_RAR;
		return;
	}

	/* EBML */
	if ((packet->payload[0] == 0x1a) && (packet->payload[1] == 0x45) && (packet->payload[2] == 0xdf) && (packet->payload[3] == 0xa3)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_EBML;
		return;
	}

	/* JPG */
	if ((packet->payload[0] == 0xff) && (packet->payload[1] ==0xd8)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_JPG;
		return;
	}

	/* GIF */
	if (match_first_bytes(packet->payload, "GIF8")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_GIF;
		return;
	}

	/* PHP scripts */
	if ((packet->payload[0] == 0x3c) && (packet->payload[1] == 0x3f) && (packet->payload[2] == 0x70) && (packet->payload[3] == 0x68)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_PHP;
		return;
	}

	/* Unix scripts */
	if ((packet->payload[0] == 0x23) && (packet->payload[1] == 0x21) && (packet->payload[2] == 0x2f) && (packet->payload[3] == 0x62)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_UNIX_SCRIPT;
		return;
	}

	/* PDFs */
	if (match_first_bytes(packet->payload, "%PDF")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_PDF;
		return;
	}

	/* PNG */
	if ((packet->payload[0] == 0x89) && (packet->payload[1] == 'P') && (packet->payload[2] == 'N') && (packet->payload[3] == 'G')) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_PNG;
		return;
	}

	/* HTML */
	if (match_first_bytes(packet->payload, "<htm")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_HTML;
		return;
	}
	
	if ((packet->payload[0] == 0x0a) && (packet->payload[1] == '<') && (packet->payload[2] == '!') && (packet->payload[3] == 'D')) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_HTML;
		return;
	}

	/* 7zip */
	if ((packet->payload[0] == 0x37) && (packet->payload[1] == 0x7a) && (packet->payload[2] == 0xbc) && (packet->payload[3] == 0xaf)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_7ZIP;
		return;
	}

	/* gzip */
	if ((packet->payload[0] == 0x1f) && (packet->payload[1] == 0x8b) && (packet->payload[2] == 0x08)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_GZIP;
		return;
	}

	/* XML */
	if (match_first_bytes(packet->payload, "<!DO")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_XML;
		return;
	}

	/* FLAC */
	if (match_first_bytes(packet->payload, "fLaC")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_FLAC;
		return;
	}

	/* MP3 */
	if ((packet->payload[0] == 'I') && (packet->payload[1] == 'D') && (packet->payload[2] == '3') && (packet->payload[3] == 0x03)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_MP3;
		return;
	}
	
	if (match_first_bytes(packet->payload, "\xff\xfb\x90\xc0")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_MP3;
		return;
	}

	/* RPM */
	if ((packet->payload[0] == 0xed) && (packet->payload[1] == 0xab) && (packet->payload[2] == 0xee) && (packet->payload[3] == 0xdb)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_RPM;
		return;
	}

	/* Wz Patch */
	if (match_first_bytes(packet->payload, "WzPa")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_WZ_PATCH;
		return;
	}

	/* Flash Video */
	if ((packet->payload[0] == 'F') && (packet->payload[1] == 'L') && (packet->payload[2] == 'V') && (packet->payload[3] == 0x01)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_FLASH;
		return;
	}

	/* .BKF (Microsoft Tape Format) */
	if (match_first_bytes(packet->payload, "TAPE")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_BKF;
		return;
	}

	/* MS Office Doc file - this is unpleasantly geeky */
	if ((packet->payload[0] == 0xd0) && (packet->payload[1] == 0xcf) && (packet->payload[2] == 0x11) && (packet->payload[3] == 0xe0)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_DOC;
		return;
	}

	/* ASP */
	if ((packet->payload[0] == 0x3c) && (packet->payload[1] == 0x25) && (packet->payload[2] == 0x40) && (packet->payload[3] == 0x20)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_ASP;
		return;
	}

	/* WMS file */
	if ((packet->payload[0] == 0x3c) && (packet->payload[1] == 0x21) && (packet->payload[2] == 0x2d) && (packet->payload[3] == 0x2d)) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_WMS;
		return;
	}

	/* ar archive, typically .deb files */
	if (match_first_bytes(packet->payload, "!<ar")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_DEB;
		return;
	}

	/* Raw XML */
	if (match_first_bytes(packet->payload, "<?xm")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_XML;
		return;
	}
	
	if (match_first_bytes(packet->payload, "<iq ")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_XML;
		return;
	}

	/* SPF */
	if (match_first_bytes(packet->payload, "SPFI")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_SPF;
		return;
	}

	/* ABIF - Applied Biosystems */
	if (match_first_bytes(packet->payload, "ABIF")) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_ABIF;
		return;
	}

	/* bzip2 - other digits are also possible instead of 9 */
	if ((packet->payload[0] == 'B') && (packet->payload[1] == 'Z') && (packet->payload[2] == 'h') && (packet->payload[3] == '9')) {
	  	flow->ndpi_result_content = NDPI_RESULT_CONTENT_BZIP2;
		return;
	}
	
	/* Break after 10 packets. */
	if ((flow->ndpi_result_content == NDPI_RESULT_CONTENT_STILL_UNKNOWN) && (flow->packet_counter > 20)) {
		NDPI_LOG(0, ndpi_struct, NDPI_LOG_DEBUG, "Could not find any raw content.\n");
		flow->ndpi_result_content = NDPI_RESULT_CONTENT_UNKNOWN;
		return;
	}
}

void ndpi_register_content_raw (struct ndpi_detection_module_struct *ndpi_mod) {

  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_AVI, "AVI", ndpi_search_raw_content);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_EXE, "EXE", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_OGG, "OGG", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_ZIP, "ZIP", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_MPEG, "MPEG", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_RAR, "RAR", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_EBML, "EBML", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_JPG, "JPG", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_GIF, "GIF", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_PHP, "PHP", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_UNIX_SCRIPT, "UNIX_Script", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_PDF, "PDF", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_PNG, "PNG", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_HTML, "HTML", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_7ZIP, "7zip", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_GZIP, "Gzip", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_XML, "XML", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_FLAC, "FLAC", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_MP3, "MP3", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_RPM, "RPM", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_WZ_PATCH, "Wz_Patch", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_FLASH, "Flash_Video", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_BKF, "BKF_Microsoft_Tape", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_DOC, "DOC", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_ASP, "ASP", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_WMS, "WMS", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_DEB, "DEB", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_SPF, "SPF", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_ABIF, "ABIF", NULL);
  ndpi_initialize_scanner_content (ndpi_mod, NDPI_RESULT_CONTENT_BZIP2, "Bzip2", NULL);
}
