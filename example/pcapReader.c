/*
 * pcapReader.c
 *
 * Copyright (C) 2011-14 - ntop.org
 * Copyright (C) 2009-2011 by ipoque GmbH
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

#ifndef WIN32
#define _GNU_SOURCE
#include <sched.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#ifdef WIN32
#include <winsock2.h> /* winsock.h is included automatically */
#include <process.h>
#include <io.h>
#include <getopt.h>
#define getopt getopt____
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>
#include <pthread.h>

#include "../config.h"
#include "linux_compat.h"
#include "ndpi_main.h"

#if defined(__OpenBSD__)
#include <sys/socket.h>
#endif

#define MAX_NUM_READER_THREADS     16

/**
 * @brief Set main components necessary to the detection
 * @details TODO
 */
static void setupDetection(u_int16_t thread_id);

/**
 * Client parameters
 */
static char *_pcap_file[MAX_NUM_READER_THREADS]; /**< Ingress pcap file/interafaces */
static char *_bpf_filter      = NULL; /**< bpf filter  */
static char *_protoFilePath   = NULL; /**< Protocol file path  */
static int _pcap_datalink_type = 0;

/**
 * User preferences
 */
static u_int8_t enable_protocol_guess = 1, verbose = 0, nDPI_traceLevel = 0;
static u_int16_t decode_tunnels = 0;
static u_int16_t num_loops = 1;
static u_int8_t shutdown_app = 0;
static u_int8_t num_threads = 1;
#ifndef WIN32
static int core_affinity[MAX_NUM_READER_THREADS];
#endif

/**
 * Detection parameters
 */
static u_int32_t detection_tick_resolution = 1000;
static time_t capture_until = 0;

#define IDLE_SCAN_PERIOD           10 /* msec (use detection_tick_resolution = 1000) */
#define MAX_IDLE_TIME           30000
#define IDLE_SCAN_BUDGET         1024

#define NUM_ROOTS                 512

static u_int32_t num_flows;

struct thread_stats {
  u_int32_t guessed_flow_protocols;
  u_int64_t raw_packet_count;
  u_int64_t ip_packet_count;
  u_int64_t total_wire_bytes, total_ip_bytes, total_discarded_bytes;
  u_int64_t protocol_counter[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int64_t protocol_counter_bytes[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t protocol_flows[NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1];
  u_int32_t ndpi_flow_count;
  u_int64_t tcp_count, udp_count;
  u_int64_t mpls_count, pppoe_count, vlan_count, fragmented_count;
  u_int64_t packet_len[6];
  u_int16_t max_packet_len;
};

struct reader_thread {
  struct ndpi_detection_module_struct *ndpi_struct;
  void *ndpi_flows_root[NUM_ROOTS];
  char _pcap_error_buffer[PCAP_ERRBUF_SIZE];
  pcap_t *_pcap_handle;
  u_int64_t last_time;
  u_int64_t last_idle_scan_time;
  u_int32_t idle_scan_idx;
  u_int32_t num_idle_flows;
  pthread_t pthread;

  /* TODO Add barrier */
  struct thread_stats stats;

  struct ndpi_flow *idle_flows[IDLE_SCAN_BUDGET];
};

static struct reader_thread ndpi_thread_info[MAX_NUM_READER_THREADS];

#define GTP_U_V1_PORT        2152
#define MAX_NDPI_FLOWS  200000000
/**
 * @brief ID tracking
 */
typedef struct ndpi_id {
  u_int8_t ip[4];				//< Ip address
  struct ndpi_id_struct *ndpi_id;		//< nDpi worker structure
} ndpi_id_t;

static u_int32_t size_id_struct = 0;		//< ID tracking structure size

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

// flow tracking
typedef struct ndpi_flow {
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  u_int8_t detection_completed, protocol;
  u_int16_t __padding;
  struct ndpi_flow_struct *ndpi_flow;
  char lower_name[32], upper_name[32];

  u_int64_t last_seen;

  u_int32_t packets, bytes;
  // result only, not used for flow identification
  u_int32_t detected_protocol;

  char host_server_name[256];

  void *src_id, *dst_id;
} ndpi_flow_t;


static u_int32_t size_flow_struct = 0;

static void help(u_int long_help) {
  printf("pcapReader -i <file|device> [-f <filter>][-s <duration>]\n"
	 "          [-p <protos>][-l <loops>[-d][-h][-t][-v <level>]\n"
	 "          [-n <threads>]\n\n"
	 "Usage:\n"
	 "  -i <file.pcap|device>     | Specify a pcap file to read packets from or a device for live capture (comma-separated list)\n"
	 "  -f <BPF filter>           | Specify a BPF filter for filtering selected traffic\n"
	 "  -s <duration>             | Maximum capture duration in seconds (live traffic capture only)\n"
	 "  -p <file>.protos          | Specify a protocol file (eg. protos.txt)\n"
	 "  -l <num loops>            | Number of detection loops (test only)\n"
	 "  -n <num threads>          | Number of threads. Default: number of interfaces in -i\n"
         "  -g <id:id...>             | Thread affinity mask (one core id per thread)\n"
	 "  -d                        | Disable protocol guess and use only DPI\n"
	 "  -t                        | Dissect GTP tunnels\n"
	 "  -h                        | This help\n"
	 "  -v <1|2>                  | Verbose 'unknown protocol' packet print. 1=verbose, 2=very verbose\n"
	 "  -V <1|2>                  | Verbose nDPI trace log print. 1=trace, 2=debug\n");

  if(long_help) {
    printf("\n\nSupported protocols:\n");
    num_threads = 1;
    setupDetection(0);
    ndpi_dump_protocols(ndpi_thread_info[0].ndpi_struct);
  }

  exit(!long_help);
}

/* ***************************************************** */

static void parseOptions(int argc, char **argv) {
  char *__pcap_file = NULL, *bind_mask = NULL;
  int thread_id, opt;
#ifndef WIN32
  u_int num_cores = sysconf( _SC_NPROCESSORS_ONLN );
#endif

  while ((opt = getopt(argc, argv, "df:g:i:hp:l:s:tv:V:n:")) != EOF) {
    switch (opt) {
    case 'd':
      enable_protocol_guess = 0;
      break;

    case 'i':
      _pcap_file[0] = optarg;
      break;

    case 'f':
      _bpf_filter = optarg;
      break;

    case 'g':
      bind_mask = optarg;
      break;

    case 'l':
      num_loops = atoi(optarg);
      break;

    case 'n':
      num_threads = atoi(optarg);
      break;

    case 'p':
      _protoFilePath = optarg;
      break;

    case 's':
      capture_until = atoi(optarg);
      break;

    case 't':
      decode_tunnels = 1;
      break;

    case 'v':
      verbose = atoi(optarg);
      break;

    case 'V':
      printf("%d\n",atoi(optarg) );
      nDPI_traceLevel  = atoi(optarg);
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
  if (_pcap_file[0] == NULL || strcmp(_pcap_file[0], "") == 0) {
    help(0);
  }

  if (strchr(_pcap_file[0], ',')) { /* multiple ingress interfaces */
    num_threads = 0; /* setting number of threads = number of interfaces */
    __pcap_file = strtok(_pcap_file[0], ",");
    while (__pcap_file != NULL && num_threads < MAX_NUM_READER_THREADS) {
      _pcap_file[num_threads++] = __pcap_file;
      __pcap_file = strtok(NULL, ",");
    }
  } else {
    if (num_threads > MAX_NUM_READER_THREADS) num_threads = MAX_NUM_READER_THREADS;
    for (thread_id = 1; thread_id < num_threads; thread_id++)
      _pcap_file[thread_id] = _pcap_file[0];
  }

#ifndef WIN32
  for (thread_id = 0; thread_id < num_threads; thread_id++)
    core_affinity[thread_id] = -1; 

  if (num_cores > 1 && bind_mask != NULL) {
    char *core_id = strtok(bind_mask, ":");
    thread_id = 0;
    while (core_id != NULL && thread_id < num_threads) {
      core_affinity[thread_id++] = atoi(core_id) % num_cores;
      core_id = strtok(NULL, ":");
    }
  }
#endif
}

/* ***************************************************** */

static void debug_printf(u_int32_t protocol, void *id_struct,
			 ndpi_log_level_t log_level,
			 const char *format, ...) {
  va_list va_ap;
#ifndef WIN32
  struct tm result;
#endif

  if(log_level <= nDPI_traceLevel) {
    char buf[8192], out_buf[8192];
    char theDate[32];
    const char *extra_msg = "";
    time_t theTime = time(NULL);

    va_start (va_ap, format);

    if (log_level == NDPI_LOG_ERROR)
      extra_msg = "ERROR: ";
    else if (log_level == NDPI_LOG_TRACE)
      extra_msg = "TRACE: ";
    else
      extra_msg = "DEBUG: ";

    memset(buf, 0, sizeof(buf));
    strftime(theDate, 32, "%d/%b/%Y %H:%M:%S", localtime_r(&theTime,&result) );
    vsnprintf(buf, sizeof(buf)-1, format, va_ap);

    snprintf(out_buf, sizeof(out_buf), "%s %s%s", theDate, extra_msg, buf);
    printf("%s", out_buf);
    fflush(stdout);
  }

  va_end(va_ap);
}

/* ***************************************************** */

static void *malloc_wrapper(unsigned long size) {
  return malloc(size);
}

/* ***************************************************** */

static void free_wrapper(void *freeable) {
  free(freeable);
}

/* ***************************************************** */

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
  case IPPROTO_IGMP:
    return("IGMP");
    break;
  }

  snprintf(proto, sizeof(proto), "%u", proto_id);
  return(proto);
}

/* ***************************************************** */

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
    if(byte > 0) {
      *--cp = byte % 10 + '0';
      byte /= 10;
      if(byte > 0)
	*--cp = byte + '0';
    }
    *--cp = '.';
    addr >>= 8;
  } while (--n > 0);

  /* Convert the string to lowercase */
  retStr = (char*)(cp+1);

  return(retStr);
}

/* ***************************************************** */

static void printFlow(u_int16_t thread_id, struct ndpi_flow *flow) {
  printf("\t%u", ++num_flows);

  printf("\t%s %s:%u <-> %s:%u ",
	 ipProto2Name(flow->protocol),
	 flow->lower_name, ntohs(flow->lower_port),
	 flow->upper_name, ntohs(flow->upper_port));

  printf("[proto: %u/%s][%u pkts/%u bytes][%s]\n",
	 flow->detected_protocol,
	 ndpi_get_proto_name(ndpi_thread_info[thread_id].ndpi_struct, flow->detected_protocol),
	 flow->packets, flow->bytes,
	 flow->host_server_name);
}

/* ***************************************************** */

static void free_ndpi_flow(struct ndpi_flow *flow) {
  if(flow->ndpi_flow) { ndpi_free(flow->ndpi_flow); flow->ndpi_flow = NULL; }
  if(flow->src_id)    { ndpi_free(flow->src_id); flow->src_id = NULL;       }
  if(flow->dst_id)    { ndpi_free(flow->dst_id); flow->dst_id = NULL;       }
}

/* ***************************************************** */

static void ndpi_flow_freer(void *node) {
  struct ndpi_flow *flow = (struct ndpi_flow*)node;

  free_ndpi_flow(flow);
  ndpi_free(flow);
}

/* ***************************************************** */

static void node_idle_scan_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow **) node;
  u_int16_t thread_id = *((u_int16_t *) user_data);

  if (ndpi_thread_info[thread_id].num_idle_flows == IDLE_SCAN_BUDGET) /* TODO optimise with a budget-based walk */
    return;

  if ((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if (flow->last_seen + MAX_IDLE_TIME < ndpi_thread_info[thread_id].last_time) {
      free_ndpi_flow(flow);
      /* adding to a queue (we can't delete it from the tree inline ) */
      ndpi_thread_info[thread_id].idle_flows[ndpi_thread_info[thread_id].num_idle_flows++] = flow;
    }
  }
}

/* ***************************************************** */

static void node_print_unknown_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if(flow->detected_protocol != 0 /* UNKNOWN */) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
    printFlow(thread_id, flow);
}

/* ***************************************************** */

static void node_print_known_proto_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

  if(flow->detected_protocol == 0 /* UNKNOWN */) return;

  if((which == ndpi_preorder) || (which == ndpi_leaf)) /* Avoid walking the same node multiple times */
    printFlow(thread_id, flow);
}

/* ***************************************************** */

static unsigned int node_guess_undetected_protocol(u_int16_t thread_id,
						   struct ndpi_flow *flow) {
  flow->detected_protocol = ndpi_guess_undetected_protocol(ndpi_thread_info[thread_id].ndpi_struct,
							   flow->protocol,
							   ntohl(flow->lower_ip),
							   ntohs(flow->lower_port),
							   ntohl(flow->upper_ip),
							   ntohs(flow->upper_port));
  // printf("Guess state: %u\n", flow->detected_protocol);
  if(flow->detected_protocol != 0)
    ndpi_thread_info[thread_id].stats.guessed_flow_protocols++;

  return flow->detected_protocol;
}

/* ***************************************************** */

static void node_proto_guess_walker(const void *node, ndpi_VISIT which, int depth, void *user_data) {
  struct ndpi_flow *flow = *(struct ndpi_flow**)node;
  u_int16_t thread_id = *((u_int16_t*)user_data);

#if 0
  printf("<%d>Walk on node %s (%p)\n",
	 depth,
	 which == preorder?"preorder":
	 which == postorder?"postorder":
	 which == endorder?"endorder":
	 which == leaf?"leaf": "unknown",
	 flow);
#endif

  if((which == ndpi_preorder) || (which == ndpi_leaf)) { /* Avoid walking the same node multiple times */
    if(enable_protocol_guess) {
      if(flow->detected_protocol == 0 /* UNKNOWN */) {
	node_guess_undetected_protocol(thread_id, flow);
	// printFlow(thread_id, flow);
      }
    }

    ndpi_thread_info[thread_id].stats.protocol_counter[flow->detected_protocol]       += flow->packets;
    ndpi_thread_info[thread_id].stats.protocol_counter_bytes[flow->detected_protocol] += flow->bytes;
    ndpi_thread_info[thread_id].stats.protocol_flows[flow->detected_protocol]++;
  }
}

/* ***************************************************** */

static int node_cmp(const void *a, const void *b) {
  struct ndpi_flow *fa = (struct ndpi_flow*)a;
  struct ndpi_flow *fb = (struct ndpi_flow*)b;

  if(fa->lower_ip   < fb->lower_ip  ) return(-1); else { if(fa->lower_ip   > fb->lower_ip  ) return(1); }
  if(fa->lower_port < fb->lower_port) return(-1); else { if(fa->lower_port > fb->lower_port) return(1); }
  if(fa->upper_ip   < fb->upper_ip  ) return(-1); else { if(fa->upper_ip   > fb->upper_ip  ) return(1); }
  if(fa->upper_port < fb->upper_port) return(-1); else { if(fa->upper_port > fb->upper_port) return(1); }
  if(fa->protocol   < fb->protocol  ) return(-1); else { if(fa->protocol   > fb->protocol  ) return(1); }

  return(0);
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow(u_int16_t thread_id,
				       const u_int8_t version,
				       const struct ndpi_iphdr *iph,
				       u_int16_t ip_offset,
				       u_int16_t ipsize,
				       u_int16_t l4_packet_len,
				       struct ndpi_id_struct **src,
				       struct ndpi_id_struct **dst,
				       u_int8_t *proto,
				       const struct ndpi_ip6_hdr *iph6) {
  u_int32_t idx, l4_offset;
  struct ndpi_tcphdr *tcph = NULL;
  struct ndpi_udphdr *udph = NULL;
  u_int32_t lower_ip;
  u_int32_t upper_ip;
  u_int16_t lower_port;
  u_int16_t upper_port;
  struct ndpi_flow flow;
  void *ret;

  /*
    Note: to keep things simple (pcapReader is just a demo app)
    we handle IPv6 a-la-IPv4.
  */
  if(version == 4) {
    if(ipsize < 20)
      return NULL;

    if((iph->ihl * 4) > ipsize || ipsize < ntohs(iph->tot_len)
       || (iph->frag_off & htons(0x1FFF)) != 0)
      return NULL;
  }

  if(l4_packet_len < 64)
    ndpi_thread_info[thread_id].stats.packet_len[0]++;
  else if(l4_packet_len >= 64 && l4_packet_len < 128)
    ndpi_thread_info[thread_id].stats.packet_len[1]++;
  else if(l4_packet_len >= 128 && l4_packet_len < 256)
    ndpi_thread_info[thread_id].stats.packet_len[2]++;
  else if(l4_packet_len >= 256 && l4_packet_len < 1024)
    ndpi_thread_info[thread_id].stats.packet_len[3]++;
  else if(l4_packet_len >= 1024 && l4_packet_len < 1500)
    ndpi_thread_info[thread_id].stats.packet_len[4]++;
  else if(l4_packet_len >= 1500)
    ndpi_thread_info[thread_id].stats.packet_len[5]++;

  if(l4_packet_len > ndpi_thread_info[thread_id].stats.max_packet_len)
    ndpi_thread_info[thread_id].stats.max_packet_len = l4_packet_len;

  if(iph->saddr < iph->daddr) {
    lower_ip = iph->saddr;
    upper_ip = iph->daddr;
  } else {
    lower_ip = iph->daddr;
    upper_ip = iph->saddr;
  }

  *proto = iph->protocol;
  l4_offset = iph->ihl * 4;
  if(iph->protocol == 6 && l4_packet_len >= 20) {
    ndpi_thread_info[thread_id].stats.tcp_count++;

    // tcp
    tcph = (struct ndpi_tcphdr *) ((u_int8_t *) iph + l4_offset);
    if(iph->saddr < iph->daddr) {
      lower_port = tcph->source;
      upper_port = tcph->dest;
    } else {
      lower_port = tcph->dest;
      upper_port = tcph->source;

      if(iph->saddr == iph->daddr) {
	if(lower_port > upper_port) {
	  u_int16_t p = lower_port;

	  lower_port = upper_port;
	  upper_port = p;
	}
      }
    }
  } else if(iph->protocol == 17 && l4_packet_len >= 8) {
    // udp
    ndpi_thread_info[thread_id].stats.udp_count++;

    udph = (struct ndpi_udphdr *) ((u_int8_t *) iph + l4_offset);
    if(iph->saddr < iph->daddr) {
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
  flow.lower_ip = lower_ip, flow.upper_ip = upper_ip;
  flow.lower_port = lower_port, flow.upper_port = upper_port;

  if(0)
    printf("[NDPI] [%u][%u:%u <-> %u:%u]\n",
	   iph->protocol, lower_ip, ntohs(lower_port), upper_ip, ntohs(upper_port));

  idx = (lower_ip + upper_ip + iph->protocol + lower_port + upper_port) % NUM_ROOTS;
  ret = ndpi_tfind(&flow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp);

  if(ret == NULL) {
    if(ndpi_thread_info[thread_id].stats.ndpi_flow_count == MAX_NDPI_FLOWS) {
      printf("ERROR: maximum flow count (%u) has been exceeded\n", MAX_NDPI_FLOWS);
      exit(-1);
    } else {
      struct ndpi_flow *newflow = (struct ndpi_flow*)malloc(sizeof(struct ndpi_flow));

      if(newflow == NULL) {
	printf("[NDPI] %s(1): not enough memory\n", __FUNCTION__);
	return(NULL);
      }

      memset(newflow, 0, sizeof(struct ndpi_flow));
      newflow->protocol = iph->protocol;
      newflow->lower_ip = lower_ip, newflow->upper_ip = upper_ip;
      newflow->lower_port = lower_port, newflow->upper_port = upper_port;

      if(version == 4) {
	inet_ntop(AF_INET, &lower_ip, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET, &upper_ip, newflow->upper_name, sizeof(newflow->upper_name));
      } else {
	inet_ntop(AF_INET6, &iph6->ip6_src, newflow->lower_name, sizeof(newflow->lower_name));
	inet_ntop(AF_INET6, &iph6->ip6_dst, newflow->upper_name, sizeof(newflow->upper_name));
      }

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

      ndpi_tsearch(newflow, &ndpi_thread_info[thread_id].ndpi_flows_root[idx], node_cmp); /* Add */
      ndpi_thread_info[thread_id].stats.ndpi_flow_count += 1;

      *src = newflow->src_id, *dst = newflow->dst_id;
      return(newflow);
    }
  } else {
    struct ndpi_flow *flow = *(struct ndpi_flow**)ret;

    if(flow->lower_ip == lower_ip && flow->upper_ip == upper_ip
       && flow->lower_port == lower_port && flow->upper_port == upper_port)
      *src = flow->src_id, *dst = flow->dst_id;
    else
      *src = flow->dst_id, *dst = flow->src_id;

    return flow;
  }
}

/* ***************************************************** */

static struct ndpi_flow *get_ndpi_flow6(u_int16_t thread_id,
					const struct ndpi_ip6_hdr *iph6,
					u_int16_t ip_offset,
					struct ndpi_id_struct **src,
					struct ndpi_id_struct **dst,
					u_int8_t *proto) {
  struct ndpi_iphdr iph;

  memset(&iph, 0, sizeof(iph));
  iph.version = 4;
  iph.saddr = iph6->ip6_src.__u6_addr.__u6_addr32[2] + iph6->ip6_src.__u6_addr.__u6_addr32[3];
  iph.daddr = iph6->ip6_dst.__u6_addr.__u6_addr32[2] + iph6->ip6_dst.__u6_addr.__u6_addr32[3];
  iph.protocol = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
  return(get_ndpi_flow(thread_id, 6, &iph, ip_offset,
		       sizeof(struct ndpi_ip6_hdr),
		       ntohs(iph6->ip6_ctlun.ip6_un1.ip6_un1_plen),
		       src, dst, proto, iph6));
}

/* ***************************************************** */

static void setupDetection(u_int16_t thread_id) {
  NDPI_PROTOCOL_BITMASK all;

  memset(&ndpi_thread_info[thread_id], 0, sizeof(ndpi_thread_info[thread_id]));

  // init global detection structure
  ndpi_thread_info[thread_id].ndpi_struct = ndpi_init_detection_module(detection_tick_resolution, malloc_wrapper, free_wrapper, debug_printf);
  if(ndpi_thread_info[thread_id].ndpi_struct == NULL) {
    printf("ERROR: global structure initialization failed\n");
    exit(-1);
  }

  // enable all protocols
  NDPI_BITMASK_SET_ALL(all);
  ndpi_set_protocol_detection_bitmask2(ndpi_thread_info[thread_id].ndpi_struct, &all);

  // allocate memory for id and flow tracking
  size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();
  size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();

  // clear memory for results
  memset(ndpi_thread_info[thread_id].stats.protocol_counter, 0, sizeof(ndpi_thread_info[thread_id].stats.protocol_counter));
  memset(ndpi_thread_info[thread_id].stats.protocol_counter_bytes, 0, sizeof(ndpi_thread_info[thread_id].stats.protocol_counter_bytes));
  memset(ndpi_thread_info[thread_id].stats.protocol_flows, 0, sizeof(ndpi_thread_info[thread_id].stats.protocol_flows));

  if(_protoFilePath != NULL)
    ndpi_load_protocols_file(ndpi_thread_info[thread_id].ndpi_struct, _protoFilePath);
}

/* ***************************************************** */

static void terminateDetection(u_int16_t thread_id) {
  int i;

  for(i=0; i<NUM_ROOTS; i++) {
    ndpi_tdestroy(ndpi_thread_info[thread_id].ndpi_flows_root[i], ndpi_flow_freer);
    ndpi_thread_info[thread_id].ndpi_flows_root[i] = NULL;
  }

  ndpi_exit_detection_module(ndpi_thread_info[thread_id].ndpi_struct, free_wrapper);
}

/* ***************************************************** */

// ipsize = header->len - ip_offset ; rawsize = header->len
static unsigned int packet_processing(u_int16_t thread_id,
				      const u_int64_t time,
				      const struct ndpi_iphdr *iph,
				      struct ndpi_ip6_hdr *iph6,
				      u_int16_t ip_offset,
				      u_int16_t ipsize, u_int16_t rawsize) {
  struct ndpi_id_struct *src, *dst;
  struct ndpi_flow *flow;
  struct ndpi_flow_struct *ndpi_flow = NULL;
  u_int32_t i, protocol = 0;
  u_int8_t proto;

  if(iph)
    flow = get_ndpi_flow(thread_id, 4, iph, ip_offset, ipsize,
			 ntohs(iph->tot_len) - (iph->ihl * 4),
			 &src, &dst, &proto, NULL);
  else
    flow = get_ndpi_flow6(thread_id, iph6, ip_offset, &src, &dst, &proto);

  if(flow != NULL) {
    ndpi_thread_info[thread_id].stats.ip_packet_count++;
    ndpi_thread_info[thread_id].stats.total_wire_bytes += rawsize + 24 /* CRC etc */, ndpi_thread_info[thread_id].stats.total_ip_bytes += rawsize;
    ndpi_flow = flow->ndpi_flow;
    flow->packets++, flow->bytes += rawsize;
    flow->last_seen = time;
  } else {
    return(0);
  }

  if(flow->detection_completed) return(0);

  protocol = (const u_int32_t)ndpi_detection_process_packet(ndpi_thread_info[thread_id].ndpi_struct, ndpi_flow,
							    iph ? (uint8_t *)iph : (uint8_t *)iph6,
							    ipsize, time, src, dst);

  flow->detected_protocol = protocol;

  if((flow->detected_protocol != NDPI_PROTOCOL_UNKNOWN)
     || ((proto == IPPROTO_UDP) && (flow->packets > 8))
     || ((proto == IPPROTO_TCP) && (flow->packets > 10))) {
    flow->detection_completed = 1;

#if 0
    if(flow->ndpi_flow->l4.tcp.host_server_name[0] != '\0')
      printf("%s\n", flow->ndpi_flow->l4.tcp.host_server_name);
#endif

    snprintf(flow->host_server_name, sizeof(flow->host_server_name), "%s", flow->ndpi_flow->host_server_name);
    free_ndpi_flow(flow);

    if(verbose > 1) {
      char buf1[32], buf2[32];

      if(enable_protocol_guess) {
	if(flow->detected_protocol == 0 /* UNKNOWN */) {
	  protocol = node_guess_undetected_protocol(thread_id, flow);
	}
      }

      printFlow(thread_id, flow);
    }
  }

#if 0
  if(ndpi_flow->l4.tcp.host_server_name[0] != '\0')
    printf("%s\n", ndpi_flow->l4.tcp.host_server_name);
#endif

  if (ndpi_thread_info[thread_id].last_idle_scan_time + IDLE_SCAN_PERIOD < ndpi_thread_info[thread_id].last_time) {
    /* scan for idle flows */
    ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_idle_scan_walker, &thread_id);

    /* remove idle flows (unfortunately we cannot do this inline) */
    while (ndpi_thread_info[thread_id].num_idle_flows > 0)
      ndpi_tdelete(ndpi_thread_info[thread_id].idle_flows[--ndpi_thread_info[thread_id].num_idle_flows], 
                   &ndpi_thread_info[thread_id].ndpi_flows_root[ndpi_thread_info[thread_id].idle_scan_idx], node_cmp);

    if (++ndpi_thread_info[thread_id].idle_scan_idx == NUM_ROOTS) ndpi_thread_info[thread_id].idle_scan_idx = 0;
    ndpi_thread_info[thread_id].last_idle_scan_time = ndpi_thread_info[thread_id].last_time;
  }

  return 0;
}

/* ****************************************************** */

char* formatTraffic(float numBits, int bits, char *buf) {
  char unit;

  if(bits)
    unit = 'b';
  else
    unit = 'B';

  if(numBits < 1024) {
    snprintf(buf, 32, "%lu %c", (unsigned long)numBits, unit);
  } else if(numBits < 1048576) {
    snprintf(buf, 32, "%.2f K%c", (float)(numBits)/1024, unit);
  } else {
    float tmpMBits = ((float)numBits)/1048576;

    if(tmpMBits < 1024) {
      snprintf(buf, 32, "%.2f M%c", tmpMBits, unit);
    } else {
      tmpMBits /= 1024;

      if(tmpMBits < 1024) {
	snprintf(buf, 32, "%.2f G%c", tmpMBits, unit);
      } else {
	snprintf(buf, 32, "%.2f T%c", (float)(tmpMBits)/1024, unit);
      }
    }
  }

  return(buf);
}

/* ***************************************************** */

char* formatPackets(float numPkts, char *buf) {
  if(numPkts < 1000) {
    snprintf(buf, 32, "%.2f", numPkts);
  } else if(numPkts < 1000000) {
    snprintf(buf, 32, "%.2f K", numPkts/1000);
  } else {
    numPkts /= 1000000;
    snprintf(buf, 32, "%.2f M", numPkts);
  }

  return(buf);
}

/* ***************************************************** */

static void printResults(u_int64_t tot_usec) {
  u_int32_t i;
  u_int64_t total_flow_bytes = 0;
  struct thread_stats cumulative_stats;
  int thread_id;

  memset(&cumulative_stats, 0, sizeof(cumulative_stats));

  for (thread_id = 0; thread_id < num_threads; thread_id++) {
    if (ndpi_thread_info[thread_id].stats.total_wire_bytes == 0) continue;

    for(i=0; i<NUM_ROOTS; i++)
      ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[i], node_proto_guess_walker, &thread_id);

    /* Stats aggregation */
    cumulative_stats.guessed_flow_protocols += ndpi_thread_info[thread_id].stats.guessed_flow_protocols;
    cumulative_stats.raw_packet_count += ndpi_thread_info[thread_id].stats.raw_packet_count;
    cumulative_stats.ip_packet_count += ndpi_thread_info[thread_id].stats.ip_packet_count;
    cumulative_stats.total_wire_bytes += ndpi_thread_info[thread_id].stats.total_wire_bytes;
    cumulative_stats.total_ip_bytes += ndpi_thread_info[thread_id].stats.total_ip_bytes;
    cumulative_stats.total_discarded_bytes += ndpi_thread_info[thread_id].stats.total_discarded_bytes;
    for (i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1; i++)
      cumulative_stats.protocol_counter[i] += ndpi_thread_info[thread_id].stats.protocol_counter[i];
    for (i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1; i++)
      cumulative_stats.protocol_counter_bytes[i] += ndpi_thread_info[thread_id].stats.protocol_counter_bytes[i];
    for (i = 0; i < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS + 1; i++)
      cumulative_stats.protocol_flows[i] += ndpi_thread_info[thread_id].stats.protocol_flows[i];
    cumulative_stats.ndpi_flow_count += ndpi_thread_info[thread_id].stats.ndpi_flow_count;
    cumulative_stats.tcp_count += ndpi_thread_info[thread_id].stats.tcp_count;
    cumulative_stats.udp_count += ndpi_thread_info[thread_id].stats.udp_count;
    cumulative_stats.mpls_count += ndpi_thread_info[thread_id].stats.mpls_count;
    cumulative_stats.pppoe_count += ndpi_thread_info[thread_id].stats.pppoe_count; 
    cumulative_stats.vlan_count += ndpi_thread_info[thread_id].stats.vlan_count;
    cumulative_stats.fragmented_count += ndpi_thread_info[thread_id].stats.fragmented_count;
    for (i = 0; i < 6; i++)
      cumulative_stats.packet_len[i] += ndpi_thread_info[thread_id].stats.packet_len[i];
    cumulative_stats.max_packet_len += ndpi_thread_info[thread_id].stats.max_packet_len;
  }
 
  printf("\nTraffic statistics:\n");
  printf("\tEthernet bytes:        %-13llu (includes ethernet CRC/IFC/trailer)\n",
	 (long long unsigned int)cumulative_stats.total_wire_bytes);
  printf("\tDiscarded bytes:       %-13llu\n",
	 (long long unsigned int)cumulative_stats.total_discarded_bytes);
  printf("\tIP packets:            %-13llu of %llu packets total\n",
	 (long long unsigned int)cumulative_stats.ip_packet_count,
	 (long long unsigned int)cumulative_stats.raw_packet_count);
  printf("\tIP bytes:              %-13llu (avg pkt size %u bytes)\n",
	 (long long unsigned int)cumulative_stats.total_ip_bytes,
	 (unsigned int)(cumulative_stats.total_ip_bytes/cumulative_stats.raw_packet_count));
  printf("\tUnique flows:          %-13u\n", cumulative_stats.ndpi_flow_count);

  printf("\tTCP Packets:           %-13lu\n", (unsigned long)cumulative_stats.tcp_count);
  printf("\tUDP Packets:           %-13lu\n", (unsigned long)cumulative_stats.udp_count);
  printf("\tVLAN Packets:          %-13lu\n", (unsigned long)cumulative_stats.vlan_count);
  printf("\tMPLS Packets:          %-13lu\n", (unsigned long)cumulative_stats.mpls_count);
  printf("\tPPPoE Packets:         %-13lu\n", (unsigned long)cumulative_stats.pppoe_count);
  printf("\tFragmented Packets:    %-13lu\n", (unsigned long)cumulative_stats.fragmented_count);
  printf("\tMax Packet size:       %-13u\n",   cumulative_stats.max_packet_len);
  printf("\tPacket Len < 64:       %-13lu\n", (unsigned long)cumulative_stats.packet_len[0]);
  printf("\tPacket Len 64-128:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[1]);
  printf("\tPacket Len 128-256:    %-13lu\n", (unsigned long)cumulative_stats.packet_len[2]);
  printf("\tPacket Len 256-1024:   %-13lu\n", (unsigned long)cumulative_stats.packet_len[3]);
  printf("\tPacket Len 1024-1500:  %-13lu\n", (unsigned long)cumulative_stats.packet_len[4]);
  printf("\tPacket Len > 1500:     %-13lu\n", (unsigned long)cumulative_stats.packet_len[5]);

  if(tot_usec > 0) {
    char buf[32], buf1[32];
    float t = (float)(cumulative_stats.ip_packet_count*1000000)/(float)tot_usec;
    float b = (float)(cumulative_stats.total_wire_bytes * 8 *1000000)/(float)tot_usec;

    printf("\tnDPI throughput:       %s pps / %s/sec\n", formatPackets(t, buf), formatTraffic(b, 1, buf1));
  }

  if(enable_protocol_guess)
    printf("\tGuessed flow protos:   %-13u\n", cumulative_stats.guessed_flow_protocols);

  printf("\n\nDetected protocols:\n");
  for (i = 0; i <= ndpi_get_num_supported_protocols(ndpi_thread_info[0].ndpi_struct); i++) {
    if(cumulative_stats.protocol_counter[i] > 0) {
      printf("\t%-20s packets: %-13llu bytes: %-13llu "
	     "flows: %-13u\n",
	     ndpi_get_proto_name(ndpi_thread_info[0].ndpi_struct, i),
	     (long long unsigned int)cumulative_stats.protocol_counter[i],
	     (long long unsigned int)cumulative_stats.protocol_counter_bytes[i],
	     cumulative_stats.protocol_flows[i]);

      total_flow_bytes += cumulative_stats.protocol_counter_bytes[i];
    }
  }

  // printf("\n\nTotal Flow Traffic: %llu (diff: %llu)\n", total_flow_bytes, cumulative_stats.total_ip_bytes-total_flow_bytes);

  if(verbose) {
    printf("\n");

    num_flows = 0;
    for (thread_id = 0; thread_id < num_threads; thread_id++) {
      for(i=0; i<NUM_ROOTS; i++)
        ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[i], node_print_known_proto_walker, &thread_id);
    }

    for (thread_id = 0; thread_id < num_threads; thread_id++) {
      if (ndpi_thread_info[thread_id].stats.protocol_counter[0] > 0) {
        printf("\n\nUndetected flows:\n");
        break;
      }
    }

    num_flows = 0;
    for (thread_id = 0; thread_id < num_threads; thread_id++) {
      if (ndpi_thread_info[thread_id].stats.protocol_counter[0] > 0) {
        for(i=0; i<NUM_ROOTS; i++)
	  ndpi_twalk(ndpi_thread_info[thread_id].ndpi_flows_root[i], node_print_unknown_proto_walker, &thread_id);
      }
    }
  }
}

/* ***************************************************** */

static void closePcapFile(u_int16_t thread_id) {
  if(ndpi_thread_info[thread_id]._pcap_handle != NULL) {
    pcap_close(ndpi_thread_info[thread_id]._pcap_handle);
  }
}

/* ***************************************************** */

static void breakPcapLoop(u_int16_t thread_id) {
  if(ndpi_thread_info[thread_id]._pcap_handle != NULL) {
    pcap_breakloop(ndpi_thread_info[thread_id]._pcap_handle);
  }
}

/* ***************************************************** */

// executed for each packet in the pcap file
void sigproc(int sig) {
  static int called = 0;
  int thread_id;

  if(called) return; else called = 1;
  shutdown_app = 1;

  for(thread_id=0; thread_id<num_threads; thread_id++)
    breakPcapLoop(thread_id);
}

/* ***************************************************** */

static void openPcapFileOrDevice(u_int16_t thread_id) {
  u_int snaplen = 1514;
  int promisc = 1;
  char errbuf[PCAP_ERRBUF_SIZE];

  if((ndpi_thread_info[thread_id]._pcap_handle = pcap_open_live(_pcap_file[thread_id], snaplen, promisc, 500, errbuf)) == NULL) {
    ndpi_thread_info[thread_id]._pcap_handle = pcap_open_offline(_pcap_file[thread_id], ndpi_thread_info[thread_id]._pcap_error_buffer);
    capture_until = 0;

    if(ndpi_thread_info[thread_id]._pcap_handle == NULL) {
      printf("ERROR: could not open pcap file: %s\n", ndpi_thread_info[thread_id]._pcap_error_buffer);
      exit(-1);
    } else
      printf("Reading packets from pcap file %s...\n", _pcap_file[thread_id]);
  } else
    printf("Capturing live traffic from device %s...\n", _pcap_file[thread_id]);

  _pcap_datalink_type = pcap_datalink(ndpi_thread_info[thread_id]._pcap_handle);

  if(_bpf_filter != NULL) {
    struct bpf_program fcode;

    if(pcap_compile(ndpi_thread_info[thread_id]._pcap_handle, &fcode, _bpf_filter, 1, 0xFFFFFF00) < 0) {
      printf("pcap_compile error: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id]._pcap_handle));
    } else {
      if(pcap_setfilter(ndpi_thread_info[thread_id]._pcap_handle, &fcode) < 0) {
	printf("pcap_setfilter error: '%s'\n", pcap_geterr(ndpi_thread_info[thread_id]._pcap_handle));
      } else
	printf("Succesfully set BPF filter to '%s'\n", _bpf_filter);
    }
  }

  if(capture_until > 0) {
    printf("Capturing traffic up to %u seconds\n", (unsigned int)capture_until);

#ifndef WIN32
    alarm(capture_until);
    signal(SIGALRM, sigproc);
#endif
    capture_until += time(NULL);
  }
}

/* ***************************************************** */

static void pcap_packet_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  const struct ndpi_ethhdr *ethernet;
  struct ndpi_iphdr *iph;
  struct ndpi_ip6_hdr *iph6;
  u_int64_t time;
  u_int16_t type, ip_offset, ip_len;
  u_int16_t frag_off = 0;
  u_int8_t proto = 0;
  u_int16_t thread_id = *((u_int16_t*)args);

  // printf("[pcapReader] pcap_packet_callback : [%u.%u.%u.%u.%u -> %u.%u.%u.%u.%u]\n", ethernet->h_dest[1],ethernet->h_dest[2],ethernet->h_dest[3],ethernet->h_dest[4],ethernet->h_dest[5],ethernet->h_source[1],ethernet->h_source[2],ethernet->h_source[3],ethernet->h_source[4],ethernet->h_source[5]);
  ndpi_thread_info[thread_id].stats.raw_packet_count++;

  if((capture_until != 0) && (header->ts.tv_sec >= capture_until)) {
    if(ndpi_thread_info[thread_id]._pcap_handle != NULL)
      pcap_breakloop(ndpi_thread_info[thread_id]._pcap_handle);

    return;
  }

  time = ((uint64_t) header->ts.tv_sec) * detection_tick_resolution +
    header->ts.tv_usec / (1000000 / detection_tick_resolution);

  if(ndpi_thread_info[thread_id].last_time > time) { /* safety check */
    // printf("\nWARNING: timestamp bug in the pcap file (ts delta: %llu, repairing)\n", ndpi_thread_info[thread_id].last_time - time);
    time = ndpi_thread_info[thread_id].last_time;
  }
  ndpi_thread_info[thread_id].last_time = time;

  if(_pcap_datalink_type == DLT_NULL) {
    if(ntohl(*((u_int32_t*)packet)) == 2)
      type = ETH_P_IP;
    else
      type = 0x86DD; /* IPv6 */

    ip_offset = 4;
  } else if(_pcap_datalink_type == DLT_EN10MB) {
    ethernet = (struct ndpi_ethhdr *) packet;
    ip_offset = sizeof(struct ndpi_ethhdr);
    type = ntohs(ethernet->h_proto);
  } else if(_pcap_datalink_type == 113 /* Linux Cooked Capture */) {
    type = (packet[14] << 8) + packet[15];
    ip_offset = 16;
  } else
    return;

  while(1) {
    if(type == 0x8100 /* VLAN */) {
      type = (packet[ip_offset+2] << 8) + packet[ip_offset+3];
      ip_offset += 4;
      ndpi_thread_info[thread_id].stats.vlan_count++;
    } else if(type == 0x8847 /* MPLS */) {
      u_int32_t label = ntohl(*((u_int32_t*)&packet[ip_offset]));

      ndpi_thread_info[thread_id].stats.mpls_count++;
      type = 0x800, ip_offset += 4;

      while((label & 0x100) != 0x100) {
	ip_offset += 4;
	label = ntohl(*((u_int32_t*)&packet[ip_offset]));
      }
    } else if(type == 0x8864 /* PPPoE */) {
      ndpi_thread_info[thread_id].stats.pppoe_count++;
      type = 0x0800;
      ip_offset += 8;
    } else
      break;
  }

  iph = (struct ndpi_iphdr *) &packet[ip_offset];

  // just work on Ethernet packets that contain IP
  if(type == ETH_P_IP && header->caplen >= ip_offset) {
    frag_off = ntohs(iph->frag_off);

    proto = iph->protocol;
    if(header->caplen < header->len) {
      static u_int8_t cap_warning_used = 0;

      if(cap_warning_used == 0) {
	printf("\n\nWARNING: packet capture size is smaller than packet size, DETECTION MIGHT NOT WORK CORRECTLY\n\n");
	cap_warning_used = 1;
      }
    }
  }

  if(iph->version == 4) {
    ip_len = ((u_short)iph->ihl * 4);
    iph6 = NULL;

    if((frag_off & 0x3FFF) != 0) {
      static u_int8_t ipv4_frags_warning_used = 0;

     v4_frags_warning:
      ndpi_thread_info[thread_id].stats.fragmented_count++;
      if(ipv4_frags_warning_used == 0) {
	printf("\n\nWARNING: IPv4 fragments are not handled by this demo (nDPI supports them)\n");
	ipv4_frags_warning_used = 1;
      }

      ndpi_thread_info[thread_id].stats.total_discarded_bytes +=  header->len;
      return;
    }
  } else if(iph->version == 6) {
    iph6 = (struct ndpi_ip6_hdr *)&packet[ip_offset];
    proto = iph6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
    ip_len = sizeof(struct ndpi_ip6_hdr);
    iph = NULL;
  } else {
    static u_int8_t ipv4_warning_used = 0;

   v4_warning:
    if(ipv4_warning_used == 0) {
      printf("\n\nWARNING: only IPv4/IPv6 packets are supported in this demo (nDPI supports both IPv4 and IPv6), all other packets will be discarded\n\n");
      ipv4_warning_used = 1;
    }

    ndpi_thread_info[thread_id].stats.total_discarded_bytes +=  header->len;
    return;
  }

  if(decode_tunnels && (proto == IPPROTO_UDP)) {
    struct ndpi_udphdr *udp = (struct ndpi_udphdr *)&packet[ip_offset+ip_len];
    u_int16_t sport = ntohs(udp->source), dport = ntohs(udp->dest);

    if((sport == GTP_U_V1_PORT) || (dport == GTP_U_V1_PORT)) {
      /* Check if it's GTPv1 */
      u_int offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr);
      u_int8_t flags = packet[offset];
      u_int8_t message_type = packet[offset+1];

      if((((flags & 0xE0) >> 5) == 1 /* GTPv1 */) && (message_type == 0xFF /* T-PDU */)) {
	ip_offset = ip_offset+ip_len+sizeof(struct ndpi_udphdr)+8 /* GTPv1 header len */;

	if(flags & 0x04) ip_offset += 1; /* next_ext_header is present */
	if(flags & 0x02) ip_offset += 4; /* sequence_number is present (it also includes next_ext_header and pdu_number) */
	if(flags & 0x01) ip_offset += 1; /* pdu_number is present */

	iph = (struct ndpi_iphdr *) &packet[ip_offset];

	if(iph->version != 4) {
	  // printf("WARNING: not good (packet_id=%u)!\n", (unsigned int)ndpi_thread_info[thread_id].stats.raw_packet_count);
	  goto v4_warning;
	}
      }
    }
  }

  // process the packet
  packet_processing(thread_id, time, iph, iph6, ip_offset, header->len - ip_offset, header->len);
}

/* ******************************************************************** */

static void runPcapLoop(u_int16_t thread_id) {
  if((!shutdown_app) && (ndpi_thread_info[thread_id]._pcap_handle != NULL))
    pcap_loop(ndpi_thread_info[thread_id]._pcap_handle, -1, &pcap_packet_callback, (u_char*)&thread_id);
}

/* ******************************************************************** */

void *processing_thread(void *_thread_id) {
  long thread_id = (long) _thread_id;

#ifndef WIN32
  if (core_affinity[thread_id] >= 0) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_affinity[thread_id], &cpuset);

    if (pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset) != 0)
      fprintf(stderr, "Error while binding thread %ld to core %d\n", thread_id, core_affinity[thread_id]);
    else
      printf("Running thread %ld on core %d...\n", thread_id, core_affinity[thread_id]);
  } else
#endif 
  printf("Running thread %ld...\n", thread_id);

  runPcapLoop(thread_id);

  return NULL;
}

/* ******************************************************************** */

void test_lib() {
  struct timeval begin, end;
  u_int64_t tot_usec;
  long thread_id;


  for (thread_id = 0; thread_id < num_threads; thread_id++) {
    setupDetection(thread_id);
    openPcapFileOrDevice(thread_id);
  }

  gettimeofday(&begin, NULL);

  /* Running processing threads */
  for (thread_id = 0; thread_id < num_threads; thread_id++)
    pthread_create(&ndpi_thread_info[thread_id].pthread, NULL, processing_thread, (void *) thread_id);

  /* Waiting for completion */
  for (thread_id = 0; thread_id < num_threads; thread_id++)
    pthread_join(ndpi_thread_info[thread_id].pthread, NULL);

  gettimeofday(&end, NULL);
  tot_usec = end.tv_sec*1000000 + end.tv_usec - (begin.tv_sec*1000000 + begin.tv_usec);

  /* Printing cumulative results */
  printResults(tot_usec);

  for (thread_id = 0; thread_id < num_threads; thread_id++) {
    closePcapFile(thread_id);
    terminateDetection(thread_id);
  }
}

/* ***************************************************** */

int main(int argc, char **argv) {
  int i;

  memset(ndpi_thread_info, 0, sizeof(ndpi_thread_info));

  parseOptions(argc, argv);

  printf("\n-----------------------------------------------------------\n"
	 "* NOTE: This is demo app to show *some* nDPI features.\n"
	 "* In this demo we have implemented only some basic features\n"
	 "* just to show you what you can do with the library. Feel \n"
	 "* free to extend it and send us the patches for inclusion\n"
	 "------------------------------------------------------------\n\n");

  printf("Using nDPI (%s) [%d thread(s)]\n", ndpi_revision(), num_threads);

  signal(SIGINT, sigproc);

  for(i=0; i<num_loops; i++)
    test_lib();

  return 0;
}

/* ****************************************************** */

#ifdef WIN32
#ifndef __GNUC__
#define EPOCHFILETIME (116444736000000000i64)
#else
#define EPOCHFILETIME (116444736000000000LL)
#endif

struct timezone {
  int tz_minuteswest; /* minutes W of Greenwich */
  int tz_dsttime;     /* type of dst correction */
};

/* ***************************************************** */

#if 0
int gettimeofday(struct timeval *tv, void *notUsed) {
  tv->tv_sec = time(NULL);
  tv->tv_usec = 0;
  return(0);
}
#endif

/* ***************************************************** */

int gettimeofday(struct timeval *tv, struct timezone *tz) {
  FILETIME        ft;
  LARGE_INTEGER   li;
  __int64         t;
  static int      tzflag;

  if(tv) {
    GetSystemTimeAsFileTime(&ft);
    li.LowPart  = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;
    t  = li.QuadPart;       /* In 100-nanosecond intervals */
    t -= EPOCHFILETIME;     /* Offset to the Epoch time */
    t /= 10;                /* In microseconds */
    tv->tv_sec  = (long)(t / 1000000);
    tv->tv_usec = (long)(t % 1000000);
  }

  if(tz) {
    if(!tzflag) {
      _tzset();
      tzflag++;
    }

    tz->tz_minuteswest = _timezone / 60;
    tz->tz_dsttime = _daylight;
  }

  return 0;
}
#endif /* WIN32 */
