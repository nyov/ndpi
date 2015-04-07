/*
 * example_ndping.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
 * Copyright (C) 2014-15 Tomasz Bujlow <tomasz@bujlow.com>
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

/* ************************************************************************************************************************************************ */
/* CONFIGURATION!!! */
/* ************************************************************************************************************************************************ */

#define VERBOSE_OUTPUT 0

#define LIVE_CAPTURE 0
#define LIVE_CAPTURE_PACKETS 10000
#define LIVE_CAPTURE_INTERFACE "wlan0"

#define	MAX_NDPI_FLOWS	2000000

/* ************************************************************************************************************************************************ */
/* STUFF ASSOCIATED WITH THE TREE OF GENERATED RESULTS */
/* ************************************************************************************************************************************************ */

#define NUM_ROOTS        512

typedef struct ndpi_flow {
	u_int32_t lower_ip;
	u_int32_t upper_ip;
	u_int16_t lower_port;
	u_int16_t upper_port;
	u_int8_t detection_completed, protocol;
	struct ndpi_flow_struct *ndpi_flow_struct_pointer;
	char lower_name[32], upper_name[32];

	u_int16_t processed_packets;

} ndpi_flow_t;

static struct ndpi_flow *ndpi_flows_root[NUM_ROOTS] = { NULL };

typedef struct node_t {
	char *key;
	struct node_t *left, *right;
} ndpi_node;

typedef enum {
	ndpi_preorder,
	ndpi_postorder,
	ndpi_endorder,
	ndpi_leaf
} ndpi_VISIT;

static void ndpi_tdestroy_recurse(ndpi_node* root, void (*free_action)(void *)) {
  
	if (root->left != NULL) {
		ndpi_tdestroy_recurse(root->left, free_action);
	}
	
	if (root->right != NULL){
		ndpi_tdestroy_recurse(root->right, free_action);
	}

	(*free_action) ((void *) root->key);
	free(root);
}

void ndpi_tdestroy(void *vrootp, void (*freefct)(void *)) {
  
	ndpi_node *root = (ndpi_node *) vrootp;

	if (root != NULL) {
		ndpi_tdestroy_recurse(root, freefct);
	}
}

void *ndpi_tsearch(const void *vkey, void **vrootp, int (*compar)(const void *, const void *)) {
  
	ndpi_node *q;
	char *key = (char *) vkey;
	ndpi_node **rootp = (ndpi_node **) vrootp;

	if (rootp == (ndpi_node **) 0) {
		return ((void *) 0);
	}

	while (*rootp != (ndpi_node *) 0) {	/* Knuth's T1: */
		int r;

		if ((r = (*compar)(key, (*rootp)->key)) == 0)	/* T2: */ {
			return ((void *)*rootp);		/* we found it! */
		}
		
		rootp = (r < 0) ?
		    &(*rootp)->left :		/* T3: follow left branch */
		    &(*rootp)->right;		/* T4: follow right branch */
	}

	q = (ndpi_node *) malloc(sizeof(ndpi_node));	/* T5: key not found */

	if (q != (ndpi_node *) 0) {	/* make new node */
		*rootp = q;			/* link new node to old */
		q->key = key;			/* initialize new node */
		q->left = q->right = (ndpi_node *)0;
	}

	return ((void *) q);
}

void *ndpi_tfind(const void *vkey, void *vrootp, int (*compar)(const void *, const void *)) {
 
	char *key = (char *)vkey;
	ndpi_node **rootp = (ndpi_node **)vrootp;

	if (rootp == (ndpi_node **) 0) {
		return ((ndpi_node *) 0);
	}

	while (*rootp != (ndpi_node *) 0) {	/* T1: */
		  
		int r;
		
		if ((r = (*compar) (key, (*rootp)->key)) == 0)	/* T2: */ {
			return (*rootp);		/* key found */
		}
		
		rootp = (r < 0) ?
		    &(*rootp)->left :		/* T3: follow left branch */
		    &(*rootp)->right;		/* T4: follow right branch */
	}
	
	return (ndpi_node *) 0;
}

static void ndpi_trecurse(ndpi_node *root, void (*action)(const void *, ndpi_VISIT, int, void*), int level, void *user_data) {

	if (root->left == (ndpi_node *) 0 && root->right == (ndpi_node *) 0) {
		(*action) (root, ndpi_leaf, level, user_data);
	} else {
		  
		(*action) (root, ndpi_preorder, level, user_data);
		
		if (root->left != (ndpi_node *) 0) {
			ndpi_trecurse(root->left, action, level + 1, user_data);
		}
		
		(*action) (root, ndpi_postorder, level, user_data);
		
		if (root->right != (ndpi_node *) 0) {
			ndpi_trecurse(root->right, action, level + 1, user_data);
		}
		
		(*action) (root, ndpi_endorder, level, user_data);
	}
}

void ndpi_twalk(const void *vroot, void (*action)(const void *, ndpi_VISIT, int, void *), void *user_data) {
  
	ndpi_node *root = (ndpi_node *) vroot;

	if (root != (ndpi_node *) 0 && action != (void (*)(const void *, ndpi_VISIT, int, void*)) 0) {
		ndpi_trecurse(root, action, 0, user_data);
	}
}

/* ************************************************************************************************************************************************ */
/* MAIN APPLICATION */
/* ************************************************************************************************************************************************ */

static u_int32_t ndpi_flow_count = 0;
struct ndpi_detection_module_struct *ndpi_detection_module_struct_pointer = NULL;


static int node_cmp(const void *a, const void *b) {

	struct ndpi_flow *fa = (struct ndpi_flow*) a;
	struct ndpi_flow *fb = (struct ndpi_flow*) b;

	if (fa->lower_ip < fb->lower_ip) {
		return -1;
	} else if (fa->lower_ip > fb->lower_ip) {
		return 1;
	}

	if (fa->lower_port < fb->lower_port) {
		return -1;
	} else if (fa->lower_port > fb->lower_port) {
		return 1;
	}

	if (fa->upper_ip < fb->upper_ip) {
		return -1;
	} else if (fa->upper_ip > fb->upper_ip) {
		return 1;
	}

	if (fa->upper_port < fb->upper_port) {
		return -1;
	} else if (fa->upper_port > fb->upper_port) {
		return 1;
	}

	if (fa->protocol < fb->protocol) {
		return -1;
	} else if (fa->protocol > fb->protocol) {
		return 1;
	}

	return 0;
}

static void free_ndpi_flow(struct ndpi_flow *flow) {
	if (flow->ndpi_flow_struct_pointer) {
		free(flow->ndpi_flow_struct_pointer);
		flow->ndpi_flow_struct_pointer = NULL;
	}
}

static void ndpi_flow_freer(void *node) {
	struct ndpi_flow *flow = (struct ndpi_flow*) node;
	free_ndpi_flow(flow);
	free(flow);
}

static struct ndpi_flow *get_ndpi_flow(const struct ndpi_iphdr *iph, u_int16_t ipsize, u_int16_t l4_packet_len) {
	  
	u_int32_t idx, l4_offset;
	struct ndpi_tcphdr *tcph = NULL;
	struct ndpi_udphdr *udph = NULL;
	u_int32_t lower_ip;
	u_int32_t upper_ip;
	u_int16_t lower_port;
	u_int16_t upper_port;
	struct ndpi_flow flow;
	void *ret;

	if (ipsize < 20) {
		return NULL;
	}

	if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len) || (iph->frag_off & htons(0x1FFF)) != 0) {
		return NULL;
	}

	if (iph->saddr < iph->daddr) {
		lower_ip = iph->saddr;
		upper_ip = iph->daddr;
	} else {
		lower_ip = iph->daddr;
		upper_ip = iph->saddr;
	}

	l4_offset = iph->ihl * 4;

	if (iph->protocol == 6 && l4_packet_len >= 20) {
		// tcp
		tcph = (struct ndpi_tcphdr *) ((u_int8_t *) iph + l4_offset);

		if (iph->saddr < iph->daddr) {
			lower_port = tcph->source;
			upper_port = tcph->dest;
		} else {
			  lower_port = tcph->dest;
			upper_port = tcph->source;
		}
	} else if (iph->protocol == 17 && l4_packet_len >= 8) {
		// udp
		udph = (struct ndpi_udphdr *) ((u_int8_t *) iph + l4_offset);

		if (iph->saddr < iph->daddr) {
			lower_port = udph->source;
			upper_port = udph->dest;
		} else {
			lower_port = udph->dest;
			upper_port = udph->source;
		}
	} else {
		// non tcp/udp protocols
		lower_port = 0;
		upper_port = 0;
	}

	flow.protocol = iph->protocol;
	flow.lower_ip = lower_ip;
	flow.upper_ip = upper_ip;
	flow.lower_port = lower_port;
	flow.upper_port = upper_port;

	idx = (lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
	ret = ndpi_tfind(&flow, (void*)&ndpi_flows_root[idx], node_cmp);

	if (ret == NULL) {
	  
		if (ndpi_flow_count == MAX_NDPI_FLOWS) {
			printf("\nERROR: maximum number of flows supported by this demo application (%u) has been exceeded! New flows from this source (PCAP file or interface) will be discarded!\n", MAX_NDPI_FLOWS);
			return NULL;
		}

		struct ndpi_flow *newflow = (struct ndpi_flow*) malloc(sizeof(struct ndpi_flow));

		if (newflow == NULL) {
			printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
			return NULL;
		}

		memset(newflow, 0, sizeof(struct ndpi_flow));
		newflow->protocol = iph->protocol;
		newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
		newflow->lower_port = lower_port, newflow->upper_port = upper_port;

		inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
		inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));

		if ((newflow->ndpi_flow_struct_pointer = create_ndpi_flow_struct_pointer()) == NULL) {
			printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
			return NULL;
		}

		ndpi_tsearch(newflow, (void*)&ndpi_flows_root[idx], node_cmp); /* Add */

		return newflow;

	} else {
		struct ndpi_flow *flow = *(struct ndpi_flow**) ret;
		return flow;
	}
}

void print_flow(char *pcap_file_name, struct ndpi_flow *flow) {
  
	char buffer[50];
	
	char result[1000];
	strcpy(result, pcap_file_name);
	
	strcat(result, "  (");
	sprintf(buffer, "%u", flow->processed_packets);
	strcat(result, buffer);
	strcat(result, " pckts) ");
	
	if (strlen(result) <=50) {
	  for (int i = 0; i < (50 - strlen(result)); i++) {
	    strcat(result, " ");
	  }
	}
	
	sprintf(buffer, "\t%s:%u <-> %s:%u ", flow->lower_name, ntohs(flow->lower_port), flow->upper_name, ntohs(flow->upper_port));
	strcat(result, buffer);
	
	for (int i = 0; i < (50 - strlen(buffer)); i++) {
	  strcat(result, " ");
	}
	
	strcat(result, "proto: ");
	strcat(result, ndpi_get_result_ip_name(ndpi_detection_module_struct_pointer, flow->ndpi_flow_struct_pointer));
	
	if ((ndpi_get_result_base_id(flow->ndpi_flow_struct_pointer) != NDPI_RESULT_BASE_STILL_UNKNOWN) && (ndpi_get_result_base_id(flow->ndpi_flow_struct_pointer) != NDPI_RESULT_BASE_UNKNOWN)) {
	  strcat(result, "->");
	  strcat(result, ndpi_get_result_base_name(ndpi_detection_module_struct_pointer, flow->ndpi_flow_struct_pointer));
	}
	
	if ((ndpi_get_result_app_id(flow->ndpi_flow_struct_pointer) != NDPI_RESULT_APP_STILL_UNKNOWN) && (ndpi_get_result_app_id(flow->ndpi_flow_struct_pointer) != NDPI_RESULT_APP_UNKNOWN)) {
	  strcat(result, "->");
	  strcat(result, ndpi_get_result_app_name(ndpi_detection_module_struct_pointer, flow->ndpi_flow_struct_pointer));
	}
	
	if ((ndpi_get_result_content_id(flow->ndpi_flow_struct_pointer) != NDPI_RESULT_CONTENT_STILL_UNKNOWN) && (ndpi_get_result_content_id(flow->ndpi_flow_struct_pointer) != NDPI_RESULT_CONTENT_UNKNOWN)) {
	  strcat(result, ", content: ");
	  strcat(result, ndpi_get_result_content_name(ndpi_detection_module_struct_pointer, flow->ndpi_flow_struct_pointer));
	}
	
	if (((ndpi_get_result_service_id(flow->ndpi_flow_struct_pointer) != NDPI_RESULT_SERVICE_STILL_UNKNOWN) && (ndpi_get_result_service_id(flow->ndpi_flow_struct_pointer) != NDPI_RESULT_SERVICE_UNKNOWN)) || (strlen(ndpi_get_result_domain_service_name(flow->ndpi_flow_struct_pointer)) > 0)) {
	  
	  if (ndpi_get_result_app_id(flow->ndpi_flow_struct_pointer) == NDPI_RESULT_APP_DNS) {
	    strcat(result, " (queried about service: ");
	  } else if (ndpi_get_result_app_id(flow->ndpi_flow_struct_pointer) == NDPI_RESULT_APP_NETBIOS) {
	    strcat(result, " (queried about name: ");
	  } else {
	    strcat(result, ", service: ");
	  }
	  
	  strcat(result, ndpi_get_result_service_name(ndpi_detection_module_struct_pointer, flow->ndpi_flow_struct_pointer));
	  
	  if (VERBOSE_OUTPUT && (strlen(ndpi_get_result_domain_service_name(flow->ndpi_flow_struct_pointer)) > 0)) {
	    strcat(result, " [");
	    strcat(result, ndpi_get_result_domain_service_name(flow->ndpi_flow_struct_pointer));
	    strcat(result, "]");
	  }
	  
	  if ((ndpi_get_result_app_id(flow->ndpi_flow_struct_pointer) == NDPI_RESULT_APP_DNS) || (ndpi_get_result_app_id(flow->ndpi_flow_struct_pointer) == NDPI_RESULT_APP_NETBIOS)) {
	    strcat(result, ")");
	  }
	}
	
	if (((ndpi_get_result_cdn_id(flow->ndpi_flow_struct_pointer) != NDPI_RESULT_CDN_STILL_UNKNOWN) && (ndpi_get_result_cdn_id(flow->ndpi_flow_struct_pointer) != NDPI_RESULT_CDN_UNKNOWN)) || (strlen(ndpi_get_result_domain_cdn_name(flow->ndpi_flow_struct_pointer)) > 0)) {
	  strcat(result, ", cdn: ");
	  strcat(result, ndpi_get_result_cdn_name(ndpi_detection_module_struct_pointer, flow->ndpi_flow_struct_pointer));
	  
	  if (VERBOSE_OUTPUT && (strlen(ndpi_get_result_domain_cdn_name(flow->ndpi_flow_struct_pointer)) > 0)) {
	    strcat(result, " [");
	    strcat(result, ndpi_get_result_domain_cdn_name(flow->ndpi_flow_struct_pointer));
	    strcat(result, "]");
	  }
	}
	
	printf("%s\n", result);
}

static void node_print_unknown_proto_walker(const void *node, ndpi_VISIT which, int depth, void *pcap_file_name) {
  
	struct ndpi_flow *flow = *(struct ndpi_flow**) node;

	if (flow->detection_completed) {
		return;
	}
	
	print_flow((char *) pcap_file_name, flow);
}

void handle_pcap_live_interface() {

	char pcap_error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle = pcap_open_live(LIVE_CAPTURE_INTERFACE, 1514, 1, 500, pcap_error_buffer);
	
	struct pcap_pkthdr header;
	const u_char *packet;
	int processed_packets_from_live_interface = 0;
	
	while (processed_packets_from_live_interface < LIVE_CAPTURE_PACKETS) {
	  
	  	if (processed_packets_from_live_interface >= LIVE_CAPTURE_PACKETS) {
			break;
		}
		
		while (packet = pcap_next(pcap_handle, &header)) {
			
			processed_packets_from_live_interface++;
			
			if (processed_packets_from_live_interface >= LIVE_CAPTURE_PACKETS) {
				break;
			}
		  
			u_int64_t time = ((uint64_t) header.ts.tv_sec) * 1000000 + header.ts.tv_usec;
			const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
			u_int16_t ip_offset = sizeof(struct ndpi_ethhdr);
			
			if (ntohs(ethernet->h_proto) == 0x8100 /* VLAN */) {
				ip_offset += 4;
			}
			
			struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[ip_offset];
			u_int16_t ipsize = header.len - ip_offset;
			
			struct ndpi_flow *flow = get_ndpi_flow(iph, ipsize, ntohs(iph->tot_len) - (iph->ihl * 4));
			
			if (flow == NULL) {
			  continue;
			}
			
			if (flow->detection_completed) {
			  continue;
			}
			
			flow->processed_packets++;
			
			flow->detection_completed = ndpi_process_ip_packet(ndpi_detection_module_struct_pointer, flow->ndpi_flow_struct_pointer, (uint8_t *) iph, ipsize, time);
			
			if (flow->detection_completed) {
			  print_flow(LIVE_CAPTURE_INTERFACE, flow);
			  free_ndpi_flow(flow);
			}
		}
	}
	
	pcap_close(pcap_handle);
	
	for (int i = 0; i < NUM_ROOTS; i++) {
		ndpi_twalk(ndpi_flows_root[i], node_print_unknown_proto_walker, LIVE_CAPTURE_INTERFACE);
	}
	
	for (int i = 0; i < NUM_ROOTS; i++) {
		ndpi_tdestroy(ndpi_flows_root[i], ndpi_flow_freer);
		ndpi_flows_root[i] = NULL;
	}
}

void handle_pcap_file(char *pcap_file_name) {

	char pcap_error_buffer[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle = pcap_open_offline(pcap_file_name, pcap_error_buffer);
	
	struct pcap_pkthdr header;
	const u_char *packet;
	
	while (packet = pcap_next(pcap_handle, &header)) {
		
		u_int64_t time = ((uint64_t) header.ts.tv_sec) * 1000000 + header.ts.tv_usec;
		const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
		u_int16_t ip_offset = sizeof(struct ndpi_ethhdr);
		
		if (ntohs(ethernet->h_proto) == 0x8100 /* VLAN */) {
			ip_offset += 4;
		}
		
		struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[ip_offset];
		u_int16_t ipsize = header.len - ip_offset;
		
		struct ndpi_flow *flow = get_ndpi_flow(iph, ipsize, ntohs(iph->tot_len) - (iph->ihl * 4));
		
		if (flow == NULL) {
		  continue;
		}
		
		if (flow->detection_completed) {
		  continue;
		}
		
		flow->processed_packets++;
		
		flow->detection_completed = ndpi_process_ip_packet(ndpi_detection_module_struct_pointer, flow->ndpi_flow_struct_pointer, (uint8_t *) iph, ipsize, time);
		
		if (flow->detection_completed) {
		  print_flow(pcap_file_name, flow);
		  free_ndpi_flow(flow);
		}
	}
	
	pcap_close(pcap_handle);
	
	for (int i = 0; i < NUM_ROOTS; i++) {
		ndpi_twalk(ndpi_flows_root[i], node_print_unknown_proto_walker, pcap_file_name);
	}
	
	for (int i = 0; i < NUM_ROOTS; i++) {
		ndpi_tdestroy(ndpi_flows_root[i], ndpi_flow_freer);
		ndpi_flows_root[i] = NULL;
	}
}

int main(int argc, char **argv) {

	ndpi_detection_module_struct_pointer = create_ndpi_detection_module_struct_pointer(1000000, NULL);
	
	if (LIVE_CAPTURE) {
		handle_pcap_live_interface();
		exit(0);
	}
	
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

	delete_ndpi_detection_module_struct_pointer(ndpi_detection_module_struct_pointer);
}
