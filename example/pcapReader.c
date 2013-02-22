/*
 * pcapReader.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-13 - ntop.org
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <search.h>
#include <pcap.h>

#include "linux_compat.h"
#include "ndpi_main.h"

static void setupDetection(void);

// cli options
static char *_pcap_file = NULL;
static char *_protoFilePath = NULL;

// pcap
static char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
static pcap_t *_pcap_handle = NULL;
static int _pcap_datalink_type = 0;
static u_int8_t enable_protocol_guess = 1, verbose = 0;
static u_int32_t guessed_flow_protocols = 0;
static u_int16_t decode_tunnels = 0;

// detection
static struct ndpi_detection_module_struct *ndpi_struct = NULL;
static u_int32_t detection_tick_resolution = 1000;

// results
static u_int64_t raw_packet_count = 0;
static u_int64_t ip_packet_count = 0;
static u_int64_t total_bytes = 0;
static u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
static u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + 1];
static u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS] = { 0 };


#define GTP_U_V1_PORT 2152

// id tracking
typedef struct osdpi_id {
  u_int8_t ip[4];
  struct ndpi_id_struct *ndpi_id;
} osdpi_id_t;

static u_int32_t size_id_struct = 0;

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

// flow tracking
typedef struct osdpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t protocol;
  struct ndpi_flow_struct *ndpi_flow;

  u_int16_t packets, bytes;
  // result only, not used for flow identification
  u_int32_t detected_protocol;

  void *src_id, *dst_id;
} osdpi_flow_t;

static u_int32_t size_flow_struct = 0;
#define			MAX_OSDPI_FLOWS			2000000
static struct osdpi_flow *osdpi_flows_root = NULL;
static u_int32_t osdpi_flow_count = 0;


static void help(u_int long_help) {
  printf("pcapReader -f <file>.pcap [-p <protos>][-d][-h][-t][-v]\n\n"
	 "Usage:\n"
	 "  -f <file>.pcap            | Specify a pcap file to read packets from\n"
	 "  -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
	 "  -d                        | Disable protocol guess and use only DPI\n"
	 "  -t                        | Dissect GTP tunnels\n"
	 "  -h                        | This help\n"
	 "  -v                        | Verbose 'unknown protocol' packet print\n");

  if(long_help) {
    printf("\n\nSupported protocols:\n");
    setupDetection();
    ndpi_dump_protocols(ndpi_struct);
  }

  exit(-1);
}

static void parseOptions(int argc, char **argv)
{
  int opt;

  while ((opt = getopt(argc, argv, "df:hp:tv")) != EOF) {
    switch (opt) {
    case 'd':
      enable_protocol_guess = 0;
      break;
    case 'f':
      _pcap_file = optarg;
      break;

    case 'p':
      _protoFilePath = optarg;
      break;

    case 't':
      decode_tunnels = 1;
      break;

    case 'v':
      verbose = 1;
      break;

    case 'h':
      help(1);
      break;

    default:
      help(0);
      break;
    }
  }

  // check parameters
  if (_pcap_file == NULL || strcmp(_pcap_file, "") == 0) {
    help(0);
  }
}

static void debug_printf(u_int32_t protocol, void *id_struct,
			 ndpi_log_level_t log_level,
			 const char *format, ...) {
}

static void *malloc_wrapper(unsigned long size)
{
  return malloc(size);
}

static void free_wrapper(void *freeable)
{
  free(freeable);
}


static char* ipProto2Name(u_short proto_id) {
  static char proto[8];

  switch(proto_id) {
  case IPPROTO_TCP:
    return("TCP");
    break;
  case IPPROTO_UDP:
    return("UDP");
    break;
  case IPPROTO_ICMP:
    return("ICMP");
    break;
  case 112:
    return("VRRP");
    break;
  }

  snprintf(proto, sizeof(proto), "%u", proto_id);
  return(proto);
}

/*
 * A faster replacement for inet_ntoa().
 */
char* intoaV4(unsigned int addr, char* buf, u_short bufLen) {
  char *cp, *retStr;
  uint byte;
  int n;

  cp = &buf[bufLen];
  *--cp = '\0';

  n = 4;
  do {
    byte = addr & 0xff;
    *--cp = byte % 10 + '0';
    byte /= 10;
    if (byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

static void printFlow(struct osdpi_flow *flow) {
  char buf1[32], buf2[32];

  printf("\t%s %s:%u > %s:%u [proto: %u/%s][%u pkts/%u bytes]\n",
	 ipProto2Name(flow->protocol),
	 intoaV4(ntohl(flow->lower_ip), buf1, sizeof(buf1)),
	 ntohs(flow->lower_port),
	 intoaV4(ntohl(flow->upper_ip), buf2, sizeof(buf2)),
	 ntohs(flow->upper_port),
	 flow->detected_protocol,
	 ndpi_get_proto_name(ndpi_struct, flow->detected_protocol),
	 flow->packets, flow->bytes);
}

static void node_print_unknown_proto_walker(const void *node, ndpi_VISIT which, int depth) {
  struct osdpi_flow *flow = *(struct osdpi_flow**)node;

  if (flow->detected_protocol != 0 /* UNKNOWN */) return;

  if((which == preorder) || (which == leaf)) /* Avoid walking the same node multiple times */
    printFlow(flow);
}

static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth) {
  struct osdpi_flow *flow = *(struct osdpi_flow**)node;
  char buf1[32], buf2[32];

#if 0
  printf("<%d>Walk on node %s (%p)\n",
	 depth,
	 which == preorder?"preorder":
	 which == postorder?"postorder":
	 which == endorder?"endorder":
	 which == leaf?"leaf": "unknown",
	 flow);
#endif

  if((which == preorder) || (which == leaf)) { /* Avoid walking the same node multiple times */
    if(enable_protocol_guess) {
      if (flow->detected_protocol == 0 /* UNKNOWN */) {
	flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_struct,
								 flow->protocol,
								 ntohl(flow->lower_ip),
								 ntohs(flow->lower_port),
								 ntohl(flow->upper_ip),
								 ntohs(flow->upper_port));

	if (flow->detected_protocol != 0)
	  guessed_flow_protocols++;

	// printFlow(flow);
      }
    }

    protocol_counter[flow->detected_protocol]       += flow->packets;
    protocol_counter_bytes[flow->detected_protocol] += flow->bytes;
    protocol_flows[flow->detected_protocol]++;
  }
}

static int node_cmp(const void *a, const void *b) {
  struct osdpi_flow *fa = (struct osdpi_flow*)a;
  struct osdpi_flow *fb = (struct osdpi_flow*)b;

  if(fa->lower_ip < fb->lower_ip) return(-1); else { if(fa->lower_ip > fb->lower_ip) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip < fb->upper_ip) return(-1); else { if(fa->upper_ip > fb->upper_ip) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol < fb->protocol) return(-1); else { if(fa->protocol > fb->protocol) return(1); }

  return(0);
}


static struct osdpi_flow *get_osdpi_flow(const struct ndpi_iphdr *iph, u_int16_t ipsize)
{
  u_int32_t i;
  u_int16_t l4_packet_len;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct osdpi_flow flow;
  void *ret;

  if (ipsize < 20)
    return NULL;

  if ((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
      || (iph->frag_off & htons(0x1FFF)) != 0)
    return NULL;

  l4_packet_len = ntohs(iph->tot_len) - (iph->ihl * 4);

  if (iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  if (iph->protocol == 6 && l4_packet_len >= 20) {
    // tcp
    tcph = (struct ndpi_tcphdr *) ((u_int8_t *) iph + iph->ihl * 4);
    if (iph->saddr < iph->daddr) {
      lower_port = tcph->source;
      upper_port = tcph->dest;
    } else {
      lower_port = tcph->dest;
      upper_port = tcph->source;
    }
  } else if (iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
    udph = (struct ndpi_udphdr *) ((u_int8_t *) iph + iph->ihl * 4);
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

  ret = ndpi_tfind(&flow, (void*)&osdpi_flows_root, node_cmp);

  if(ret == NULL) {
    if (osdpi_flow_count == MAX_OSDPI_FLOWS) {
      printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_OSDPI_FLOWS);
      exit(-1);
    } else {
      struct osdpi_flow *newflow = (struct osdpi_flow*)malloc(sizeof(struct osdpi_flow));

      if(newflow == NULL) {
	printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      memset(newflow, 0, sizeof(struct osdpi_flow));
      newflow->protocol = iph->protocol;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;

      if((newflow->ndpi_flow = calloc(1, size_flow_struct)) == NULL) {
	printf("[NDPI] %s(2): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      if((newflow->src_id = calloc(1, size_id_struct)) == NULL) {
	printf("[NDPI] %s(3): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      if((newflow->dst_id = calloc(1, size_id_struct)) == NULL) {
	printf("[NDPI] %s(4): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      ndpi_tsearch(newflow, (void*)&osdpi_flows_root, node_cmp); /* Add */

      osdpi_flow_count += 1;

      //printFlow(newflow);
      return(newflow);
    }
  } else
    return *(struct osdpi_flow**)ret;
}

static void setupDetection(void)
{
  u_int32_t i;
  NDPI_PROTOCOL_BITMASK all;

  // init global detection structure
  ndpi_struct = ndpi_init_detection_module(detection_tick_resolution, malloc_wrapper, free_wrapper, debug_printf);
  if (ndpi_struct == NULL) {
    printf("ERROR: global structure initialization failed\n");
    exit(-1);
  }
  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_struct, &all);

  // allocate memory for id and flow tracking
  size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
  size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

  // clear memory for results
  memset(protocol_counter, 0, (NDPI_MAX_SUPPORTED_PROTOCOLS + 1) * sizeof(u_int64_t));
  memset(protocol_counter_bytes, 0, (NDPI_MAX_SUPPORTED_PROTOCOLS + 1) * sizeof(u_int64_t));

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_struct, _protoFilePath);
}

static void free_osdpi_flow(struct osdpi_flow *flow) {
  ndpi_free(flow->ndpi_flow);
  ndpi_free(flow->src_id);
  ndpi_free(flow->dst_id);
}

static void osdpi_flow_freer(void *node) {
  struct osdpi_flow *flow = (struct osdpi_flow*)node;
  free_osdpi_flow(flow);
  ndpi_free(flow);
}


static void terminateDetection(void)
{
  ndpi_tdestroy(osdpi_flows_root, osdpi_flow_freer);
  ndpi_exit_detection_module(ndpi_struct, free_wrapper);
}

static unsigned int packet_processing(const u_int64_t time, const struct ndpi_iphdr *iph,
				      uint16_t ipsize, uint16_t rawsize)
{
  struct ndpi_id_struct *src, *dst;
  struct osdpi_flow *flow;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int32_t protocol = 0;
  u_int16_t frag_off = ntohs(iph->frag_off);

  flow = get_osdpi_flow(iph, ipsize);
  if (flow != NULL) {
    ndpi_flow = flow->ndpi_flow;
    flow->packets++, flow->bytes += rawsize;
    src = flow->src_id, dst = flow->dst_id;
  } else
    return;

  ip_packet_count++;
  total_bytes += rawsize;

  // only handle unfragmented packets
  if ((frag_off & 0x3FFF) == 0) {
    // here the actual detection is performed
    protocol = ndpi_detection_process_packet(ndpi_struct, ndpi_flow, (uint8_t *) iph, ipsize, time, src, dst);
  } else {
    static u_int8_t frag_warning_used = 0;

    if (frag_warning_used == 0) {
      printf("\n\nWARNING: fragmented ip packets are not supported and will be skipped \n\n");
      frag_warning_used = 1;
    }
    return 0;
  }

#if 0
  if(verbose && (protocol == 0)) {
    char buf1[32], buf2[32];

    printf("%s %s:%u > %s:%u [proto: %u/%s]\n",
	   ipProto2Name(flow->protocol),
	   intoaV4(ntohl(flow->lower_ip), buf1, sizeof(buf1)), ntohs(flow->lower_port),
	   intoaV4(ntohl(flow->upper_ip), buf2, sizeof(buf2)), ntohs(flow->upper_port),
	   protocol, ndpi_get_proto_name(ndpi_struct, protocol));
  }
#endif

  if (flow != NULL) {
    flow->detected_protocol = protocol;
#if 0
    if(ndpi_flow->l4.tcp.host_server_name[0] != '\0')
      printf("%s\n", ndpi_flow->l4.tcp.host_server_name);
#endif
  }

  return 0;
}

static void printResults(void)
{
  u_int32_t i, j;

  printf("\x1b[2K\n");
  printf("pcap file contains\n");
  printf("\tip packets:   \x1b[33m%-13llu\x1b[0m of %llu packets total\n",
	 (long long unsigned int)ip_packet_count,
	 (long long unsigned int)raw_packet_count);
  printf("\tip bytes:     \x1b[34m%-13llu\x1b[0m\n",
	 (long long unsigned int)total_bytes);
  printf("\tunique flows: \x1b[36m%-13u\x1b[0m\n", osdpi_flow_count);

  ndpi_twalk(osdpi_flows_root, node_proto_guess_walker);
  if(enable_protocol_guess)
    printf("\tguessed flow protocols: \x1b[35m%-13u\x1b[0m\n", guessed_flow_protocols);


  printf("\n\ndetected protocols:\n");
  for (i = 0; i <= NDPI_MAX_SUPPORTED_PROTOCOLS; i++) {

    if (protocol_counter[i] > 0) {
      printf("\t\x1b[31m%-20s\x1b[0m packets: \x1b[33m%-13llu\x1b[0m bytes: \x1b[34m%-13llu\x1b[0m "
	     "flows: \x1b[36m%-13u\x1b[0m\n",
	     ndpi_get_proto_name(ndpi_struct, i), (long long unsigned int)protocol_counter[i],
	     (long long unsigned int)protocol_counter_bytes[i], protocol_flows[i]);
    }
  }

  if(verbose && (protocol_counter[0] > 0)) {
    printf("\n\nundetected flows:\n");
    ndpi_twalk(osdpi_flows_root, node_print_unknown_proto_walker);
  }

  printf("\n\n");
}

static void openPcapFile(void)
{
  _pcap_handle = pcap_open_offline(_pcap_file, _pcap_error_buffer);

  if (_pcap_handle == NULL) {
    printf("ERROR: could not open pcap file: %s\n", _pcap_error_buffer);
    exit(-1);
  }
  _pcap_datalink_type = pcap_datalink(_pcap_handle);
}

static void closePcapFile(void)
{
  if (_pcap_handle != NULL) {
    pcap_close(_pcap_handle);
  }
}

// executed for each packet in the pcap file
static void pcap_packet_callback(u_char * args, const struct pcap_pkthdr *header, const u_char * packet)
{
  const struct ndpi_ethhdr *ethernet = (struct ndpi_ethhdr *) packet;
  struct ndpi_iphdr *iph = (struct ndpi_iphdr *) &packet[sizeof(struct ndpi_ethhdr)];
  u_int64_t time;
  static u_int64_t lasttime = 0;
  u_int16_t type, ip_offset;

  raw_packet_count++;

  time = ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
    header->ts.tv_usec / (1000000 / detection_tick_resolution);
  if (lasttime > time) {
    // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", lasttime - time);
    time = lasttime;
  }
  lasttime = time;


  type = ethernet->h_proto;

  // just work on Ethernet packets that contain IP
  if (_pcap_datalink_type == DLT_EN10MB && type == htons(ETH_P_IP)
      && header->caplen >= sizeof(struct ndpi_ethhdr)) {
    u_int16_t frag_off = ntohs(iph->frag_off);

    if(header->caplen < header->len) {
      static u_int8_t cap_warning_used = 0;
      if (cap_warning_used == 0) {
	printf("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
	cap_warning_used = 1;
      }
    }

    if (iph->version != 4) {
      static u_int8_t ipv4_warning_used = 0;

    v4_warning:
      if (ipv4_warning_used == 0) {
	printf("\n\nWARNING: only IPv4 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
	ipv4_warning_used = 1;
      }
      return;
    }

    ip_offset = sizeof(struct ndpi_ethhdr);
    if(decode_tunnels && (iph->protocol == IPPROTO_UDP) && ((frag_off & 0x3FFF) == 0)) {
      u_short ip_len = ((u_short)iph->ihl * 4);
      struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[sizeof(struct ndpi_ethhdr)+ip_len];
      u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

      if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
	/* Check if it's GTPv1 */
	u_int offset = sizeof(struct ndpi_ethhdr)+ip_len+sizeof(struct ndpi_udphdr);
	u_int8_t flags = packet[offset];
	u_int8_t message_type = packet[offset+1];

	if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
	  ip_offset = sizeof(struct ndpi_ethhdr)+ip_len+sizeof(struct ndpi_udphdr)+8 /* GTPv1 header len */;

	  if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
	  if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
	  if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

	  iph = (struct ndpi_iphdr *) &packet[ip_offset];

	  if (iph->version != 4) {
	    // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)raw_packet_count);
	    goto v4_warning;
	  }
	}
      }

    }

    // process the packet
    packet_processing(time, iph, header->len - ip_offset, header->len);
  }

}

static void runPcapLoop(void)
{

  printf("\n-----------------------------------------------------------\n"
	 "* NOTE: This is demo app to show *some* nDPI features.\n"
	 "* In this demo we have implemented only some basic features\n"
	 "* just to show you what you can do with the library. Feel \n"
	 "* free to extend it and send us the patches for inclusion\n"
	 "------------------------------------------------------------\n\n");

  if (_pcap_handle != NULL)
    pcap_loop(_pcap_handle, -1, &pcap_packet_callback, NULL);
}

int main(int argc, char **argv)
{
  parseOptions(argc, argv);

  setupDetection();

  openPcapFile();
  runPcapLoop();
  closePcapFile();

  printResults();

  terminateDetection();

  return 0;
}
