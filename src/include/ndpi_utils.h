/*
 * ndpi_utils.h
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



#ifndef _NDPI_UTILS_H_
#define _NDPI_UTILS_H_

#include "ndpi_protocols.h"

extern u_int8_t ndpi_net_match(u_int32_t ip_to_check,
			       u_int32_t net,
			       u_int32_t num_bits);

extern u_int8_t ndpi_ips_match(u_int32_t src, u_int32_t dst,
			       u_int32_t net, u_int32_t num_bits);

extern char* ndpi_strnstr(const char *s, const char *find, size_t slen);

#endif							/* _NDPI_UTILS_H_ */

