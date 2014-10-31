/*
 * example_ndping.c
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <pcap.h>
#include <dirent.h>
#include "ndpi_main.h"

struct ndpi_detection_module_struct *ndpi_detection_module_struct_pointer = NULL;
struct ndpi_flow_struct *ndpi_flow_struct_pointer = NULL;

int process_packet_by_ndpi(u_int64_t time, bpf_u_int32 header_len, u_char *packet) {

	const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
	u_int16_t ip_offset = sizeof(struct ndpi_ethhdr);

	if (ntohs(ethernet->h_proto) == 0x8100 /* VLAN */) {
		ip_offset += 4;
	}

	struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[ip_offset];
	u_int16_t ipsize = header_len - ip_offset;

	return ndpi_process_ip_packet(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer, (uint8_t *) iph, ipsize, time);
}

void handle_pcap_file(char *pcap_file_name) {

	clear_ndpi_flow_struct_pointer(ndpi_flow_struct_pointer);

	char pcap_error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle = pcap_open_offline(pcap_file_name, pcap_error_buffer);
	
	struct pcap_pkthdr header;
	const u_char *packet;
	
	unsigned long processed_packets_by_ndpi = 0;
	unsigned long processed_packets = 0;
	int flow_detected = 0;
	
	while (packet = pcap_next(pcap_handle, &header)) {
		u_int64_t time = ((uint64_t) header.ts.tv_sec) * 1000000 + header.ts.tv_usec;
		
		if (!flow_detected) {
		  flow_detected = process_packet_by_ndpi(time, header.len, (u_char *) packet);
		  processed_packets_by_ndpi++;
		}
		
		processed_packets++;
	}
	
	char no_of_packets[15];
	char result[1000];
	strcpy(result, pcap_file_name);
	
	for (int i = 0; i < (35 - strlen(pcap_file_name)); i++) {
	  strcat(result, " ");
	}
	
	strcat(result, "proto: ");
	strcat(result, ndpi_get_result_ip_name(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer));
	
	if ((ndpi_get_result_base_id(ndpi_flow_struct_pointer) != NDPI_RESULT_BASE_STILL_UNKNOWN) && (ndpi_get_result_base_id(ndpi_flow_struct_pointer) != NDPI_RESULT_BASE_UNKNOWN)) {
	  strcat(result, "->");
	  strcat(result, ndpi_get_result_base_name(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer));
	}
	
	if ((ndpi_get_result_app_id(ndpi_flow_struct_pointer) != NDPI_RESULT_APP_STILL_UNKNOWN) && (ndpi_get_result_app_id(ndpi_flow_struct_pointer) != NDPI_RESULT_APP_UNKNOWN)) {
	  strcat(result, "->");
	  strcat(result, ndpi_get_result_app_name(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer));
	}
	
	if ((ndpi_get_result_content_id(ndpi_flow_struct_pointer) != NDPI_RESULT_CONTENT_STILL_UNKNOWN) && (ndpi_get_result_content_id(ndpi_flow_struct_pointer) != NDPI_RESULT_CONTENT_UNKNOWN)) {
	  strcat(result, ", content: ");
	  strcat(result, ndpi_get_result_content_name(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer));
	}
	
	if (((ndpi_get_result_service_id(ndpi_flow_struct_pointer) != NDPI_RESULT_SERVICE_STILL_UNKNOWN) && (ndpi_get_result_service_id(ndpi_flow_struct_pointer) != NDPI_RESULT_SERVICE_UNKNOWN)) || (strlen(ndpi_get_result_domain_service_name(ndpi_flow_struct_pointer)) > 0)) {
	  strcat(result, ", service: ");
	  strcat(result, ndpi_get_result_service_name(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer));
	  
	  if (strlen(ndpi_get_result_domain_service_name(ndpi_flow_struct_pointer)) > 0) {
	    strcat(result, " [");
	    strcat(result, ndpi_get_result_domain_service_name(ndpi_flow_struct_pointer));
	    strcat(result, "]");
	  }
	}
	
	if (((ndpi_get_result_cdn_id(ndpi_flow_struct_pointer) != NDPI_RESULT_CDN_STILL_UNKNOWN) && (ndpi_get_result_cdn_id(ndpi_flow_struct_pointer) != NDPI_RESULT_CDN_UNKNOWN)) || (strlen(ndpi_get_result_domain_cdn_name(ndpi_flow_struct_pointer)) > 0)) {
	  strcat(result, ", cdn: ");
	  strcat(result, ndpi_get_result_cdn_name(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer));
	  
	  if (strlen(ndpi_get_result_domain_cdn_name(ndpi_flow_struct_pointer)) > 0) {
	    strcat(result, " [");
	    strcat(result, ndpi_get_result_domain_cdn_name(ndpi_flow_struct_pointer));
	    strcat(result, "]");
	  }
	}
	
	int len = strlen(result);
	
	for (int i = 0; i < (150 - len); i++) {
	  strcat(result, " ");
	}
	
	strcat(result, "Inspected packets: ");
	
	sprintf(no_of_packets, "%lu", processed_packets_by_ndpi);
	
	strcat(result, no_of_packets);
	strcat(result, "/");
	
	sprintf(no_of_packets, "%lu", processed_packets);
	strcat(result, no_of_packets);
	
	printf("%s\n", result);
	
	pcap_close(pcap_handle);
}

int main(int argc, char **argv) {

	ndpi_detection_module_struct_pointer = create_ndpi_detection_module_struct_pointer(1000000, NULL);
	ndpi_flow_struct_pointer = create_ndpi_flow_struct_pointer();

	DIR *dir1, *dir2;
	struct dirent *ent1, *ent2;
	char directory_string[500];

	if ((dir1 = opendir("flows")) != NULL) {
		while ((ent1 = readdir(dir1)) != NULL) {
			if (memcmp(ent1->d_name, ". ", 1) != 0) {
				printf("\n");
				printf("                                                       --------------------------  %s  --------------------------\n", ent1->d_name);

				strcpy(directory_string, "flows/");
				strcat(directory_string, ent1->d_name);

				if ((dir2 = opendir(directory_string)) != NULL) {
					while ((ent2 = readdir(dir2)) != NULL) {
						if (memcmp(ent2->d_name, ". ", 1) != 0) {
							strcpy(directory_string, "flows/");
							strcat(directory_string, ent1->d_name);
							strcat(directory_string, "/");
							strcat(directory_string, ent2->d_name);
							handle_pcap_file(directory_string);
						}
					}

					closedir(dir2);
				} else {
					perror("");
					return EXIT_FAILURE;
				}
			}
		}

		closedir(dir1);
	} else {
		perror("");
		return EXIT_FAILURE;
	}

	delete_ndpi_flow_struct_pointer(ndpi_flow_struct_pointer);
	delete_ndpi_detection_module_struct_pointer(ndpi_detection_module_struct_pointer);
}
