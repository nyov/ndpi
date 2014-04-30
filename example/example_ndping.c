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

void *malloc_wrapper(unsigned long size) {
	return malloc(size);
}

void free_wrapper(void *freeable) {
	free(freeable);
}

void process_packet_by_ndpi(u_int64_t time, bpf_u_int32 header_len, u_char *packet) {

	const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
	u_int16_t ip_offset = sizeof(struct ndpi_ethhdr);

	if (ntohs(ethernet->h_proto) == 0x8100 /* VLAN */) {
		ip_offset += 4;
	}

	struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[ip_offset];
	u_int16_t ipsize = header_len - ip_offset;

	ndpi_detection_process_packet(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer, (uint8_t *) iph, ipsize, time, NULL, NULL);
}

void handle_pcap_file(char *pcap_file_name) {

	// Detected protocol field + clear the flow structure to handle a new flow
	memset(ndpi_flow_struct_pointer, 0, ndpi_detection_get_sizeof_ndpi_flow_struct());

	char pcap_error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle = pcap_open_offline(pcap_file_name, pcap_error_buffer);
	
	struct pcap_pkthdr header;
	const u_char *packet;
	
	unsigned long processed_packets_by_ndpi = 0;
	
	while (packet = pcap_next(pcap_handle, &header)) {
		u_int64_t time = ((uint64_t) header.ts.tv_sec) * 1000000 + header.ts.tv_usec;
		process_packet_by_ndpi(time, header.len, (u_char *) packet);
		processed_packets_by_ndpi++;
	}
	
	char no_of_packets[15];
	char result[1000];
	strcpy(result, pcap_file_name);
	
	for (int i = 0; i < (35 - strlen(pcap_file_name)); i++) {
	  strcat(result, " ");
	}
	
	strcat(result, "proto: ");
	strcat(result, ndpi_get_result_ip(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer->ndpi_result_ip));
	
	if ((ndpi_flow_struct_pointer->ndpi_result_base != NDPI_RESULT_BASE_STILL_UNKNOWN) && (ndpi_flow_struct_pointer->ndpi_result_base != NDPI_RESULT_BASE_UNKNOWN)) {
	  strcat(result, "->");
	  strcat(result, ndpi_get_result_base(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer->ndpi_result_base));
	}
	
	if ((ndpi_flow_struct_pointer->ndpi_result_app != NDPI_RESULT_APP_STILL_UNKNOWN) && (ndpi_flow_struct_pointer->ndpi_result_app != NDPI_RESULT_APP_UNKNOWN)) {
	  strcat(result, "->");
	  strcat(result, ndpi_get_result_app(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer->ndpi_result_app));
	}
	
	if ((ndpi_flow_struct_pointer->ndpi_result_content != NDPI_RESULT_CONTENT_STILL_UNKNOWN) && (ndpi_flow_struct_pointer->ndpi_result_content != NDPI_RESULT_CONTENT_UNKNOWN)) {
	  strcat(result, ", content: ");
	  strcat(result, ndpi_get_result_content(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer->ndpi_result_content));
	}
	
	if ((ndpi_flow_struct_pointer->ndpi_result_service != NDPI_RESULT_SERVICE_STILL_UNKNOWN) && (ndpi_flow_struct_pointer->ndpi_result_service != NDPI_RESULT_SERVICE_UNKNOWN)) {
	  strcat(result, ", service: ");
	  strcat(result, ndpi_get_result_service(ndpi_detection_module_struct_pointer, ndpi_flow_struct_pointer->ndpi_result_service));
	}
	
	int len = strlen(result);
	
	for (int i = 0; i < (150 - len); i++) {
	  strcat(result, " ");
	}
	
	strcat(result, "Inspected packets: ");
	
	sprintf(no_of_packets, "%lu", processed_packets_by_ndpi);
	
	strcat(result, no_of_packets);
	
	printf("%s\n", result);
	
	pcap_close(pcap_handle);
}

int main(int argc, char **argv) {

	ndpi_detection_module_struct_pointer = ndpi_init_detection_module(1000000, malloc_wrapper, free_wrapper, NULL);
	ndpi_flow_struct_pointer = calloc(1, ndpi_detection_get_sizeof_ndpi_flow_struct());

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

	ndpi_free(ndpi_flow_struct_pointer);
	ndpi_flow_struct_pointer = NULL;
	ndpi_exit_detection_module(ndpi_detection_module_struct_pointer, free_wrapper);
}
