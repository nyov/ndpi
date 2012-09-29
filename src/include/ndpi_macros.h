/*
 * ndpi_macros.h
 * Copyright (C) 2009-2011 by ipoque GmbH
 * 
 * This file is part of OpenDPI, an open source deep packet inspection
 * library based on the PACE technology by ipoque GmbH
 * 
 * OpenDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * OpenDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with OpenDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */


#ifndef __NDPI_API_INCLUDE_FILE__
#error CANNOT INCLUDE THIS .H FILE, INCLUDE NDPI_API.H
#endif

#ifndef __NDPI_MACROS_H__
#define __NDPI_MACROS_H__

#ifdef __cplusplus
extern "C" {
#endif


#if NDPI_MAX_SUPPORTED_PROTOCOLS >= 128
	typedef struct ndpi_protocol_bitmask_struct {
		u64 bitmask[3];
	} ndpi_protocol_bitmask_struct_t;
#define NDPI_PROTOCOL_BITMASK struct ndpi_protocol_bitmask_struct

#elif NDPI_MAX_SUPPORTED_PROTOCOLS >= 64
	typedef struct ndpi_protocol_bitmask_struct {
		u64 bitmask[2];
	} ndpi_protocol_bitmask_struct_t;
#define NDPI_PROTOCOL_BITMASK struct ndpi_protocol_bitmask_struct

#else

#define NDPI_PROTOCOL_BITMASK u64

#endif


#if NDPI_MAX_SUPPORTED_PROTOCOLS < 64


#define NDPI_CONVERT_PROTOCOL_TO_BITMASK(p) ( ((NDPI_PROTOCOL_BITMASK)1) << (p) )
#define NDPI_SAVE_AS_BITMASK(bitmask,value) (bitmask)=(((NDPI_PROTOCOL_BITMASK)1)<<(value))
#define NDPI_BITMASK_COMPARE(a,b)	((a) & (b))
#define NDPI_BITMASK_MATCH(x,y)	((x) == (y))

// all protocols in b are also in a
#define NDPI_BITMASK_CONTAINS_BITMASK(a,b)	(((a) & (b)) == (b))

#define NDPI_BITMASK_ADD(a,b)	(a)|=(b)
#define NDPI_BITMASK_AND(a,b)	(a)&=(b)
#define NDPI_BITMASK_DEL(a,b) (a)=((a) & (~(b)))
#define NDPI_BITMASK_SET(a,b)	(a)=(b)
#define NDPI_PROTOCOL_BITMASK_NONE			((NDPI_PROTOCOL_BITMASK)0)

#define NDPI_ADD_PROTOCOL_TO_BITMASK(bmask,value) NDPI_BITMASK_ADD(bmask,NDPI_CONVERT_PROTOCOL_TO_BITMASK(value))
#define NDPI_DEL_PROTOCOL_FROM_BITMASK(bmask,value) NDPI_BITMASK_DEL(bmask,NDPI_CONVERT_PROTOCOL_TO_BITMASK(value))

#define NDPI_COMPARE_PROTOCOL_TO_BITMASK(bmask,value) NDPI_BITMASK_COMPARE(bmask,NDPI_CONVERT_PROTOCOL_TO_BITMASK(value))


#define NDPI_BITMASK_RESET(a)		(a) = 0
#define NDPI_BITMASK_SET_ALL(a)	(a) = ((NDPI_PROTOCOL_BITMASK)0xFFFFFFFFFFFFFFFFULL)


#define NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_STRING	"%llu"
#define NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(bm)	(bm)
// you can use a printf(NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_STRING,

#define NDPI_BITMASK_IS_ZERO(a) ( (a) == 0 )

#define NDPI_BITMASK_CONTAINS_NEGATED_BITMASK(a,b) ((a) & ~(b) == ~(b))

#elif NDPI_MAX_SUPPORTED_PROTOCOLS < 128

#define NDPI_SAVE_AS_BITMASK(bmask,value)						\
	{										\
	(bmask).bitmask[0] = 0;								\
	(bmask).bitmask[1] = 0;								\
	(bmask).bitmask[(value) >> 6] = (((u64)1)<<((value) & 0x3F));			\
	}

#define NDPI_BITMASK_COMPARE(a,b)	(((a).bitmask[0]) & ((b).bitmask[0]) || ((a).bitmask[1]) & ((b).bitmask[1]))

#define NDPI_BITMASK_MATCH(a,b)	(((a).bitmask[0]) == ((b).bitmask[0]) && ((a).bitmask[1]) == ((b).bitmask[1]))

// all protocols in b are also in a
#define NDPI_BITMASK_CONTAINS_BITMASK(a,b)	((((a).bitmask[0] & (b).bitmask[0]) == (b).bitmask[0]) && (((a).bitmask[1] & (b).bitmask[1]) == (b).bitmask[1]))


#define NDPI_BITMASK_ADD(a,b)		{(a).bitmask[0] |= (b).bitmask[0]; (a).bitmask[1] |= (b).bitmask[1];}
#define NDPI_BITMASK_AND(a,b)		{(a).bitmask[0] &= (b).bitmask[0]; (a).bitmask[1] &= (b).bitmask[1];}
#define NDPI_BITMASK_DEL(a,b) 	{(a).bitmask[0] = (a).bitmask[0] & (~((b).bitmask[0]));(a).bitmask[1] = (a).bitmask[1] & ( ~((b).bitmask[1]));}

#define NDPI_BITMASK_SET(a,b)		{(a).bitmask[0] = ((b).bitmask[0]); (a).bitmask[1] = (b).bitmask[1];}

#define NDPI_BITMASK_RESET(a)		{((a).bitmask[0]) = 0; ((a).bitmask[1]) = 0;}
#define NDPI_BITMASK_SET_ALL(a)		{((a).bitmask[0]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[1]) = 0xFFFFFFFFFFFFFFFFULL;}

/* this is a very very tricky macro *g*,
 * the compiler will remove all shifts here if the protocol is static...
 */
#define NDPI_ADD_PROTOCOL_TO_BITMASK(bmask,value)					\
	{(bmask).bitmask[(value) >> 6] |= (((u64)1)<<((value) & 0x3F));}		\

#define NDPI_DEL_PROTOCOL_FROM_BITMASK(bmask,value)								\
	{(bmask).bitmask[(value) >> 6] = (bmask).bitmask[(value) >> 6] & (~(((u64)1)<<((value) & 0x3F)));}	\

#define NDPI_COMPARE_PROTOCOL_TO_BITMASK(bmask,value)					\
	((bmask).bitmask[(value) >> 6] & (((u64)1)<<((value) & 0x3F)))			\


#define NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_STRING	"%16llX , %llX"
#define NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(bm)	(bm).bitmask[0] , (bm).bitmask[1]

#define NDPI_BITMASK_IS_ZERO(a) ( (a).bitmask[0] == 0 && (a).bitmask[1] == 0)

#define NDPI_BITMASK_CONTAINS_NEGATED_BITMASK(a,b) ((((a).bitmask[0] & ~(b).bitmask[0]) == ~(b).bitmask[0]) && (((a).bitmask[1] & ~(b).bitmask[1]) == ~(b).bitmask[1]))

#else

#define NDPI_SAVE_AS_BITMASK(bmask,value)           \
  {                   \
  (bmask).bitmask[0] = 0;               \
  (bmask).bitmask[1] = 0;               \
  (bmask).bitmask[2] = 0;               \
  (bmask).bitmask[(value) >> 6] = (((u64)1)<<((value) & 0x3F));     \
}

#define NDPI_BITMASK_COMPARE(a,b) (((a).bitmask[0]) & ((b).bitmask[0]) || ((a).bitmask[1]) & ((b).bitmask[1]) || ((a).bitmask[2]) & ((b).bitmask[2]))

#define NDPI_BITMASK_MATCH(a,b) (((a).bitmask[0]) == ((b).bitmask[0]) && ((a).bitmask[1]) == ((b).bitmask[1]) && ((a).bitmask[2]) == ((b).bitmask[2]))

// all protocols in b are also in a
#define NDPI_BITMASK_CONTAINS_BITMASK(a,b)  ((((a).bitmask[0] & (b).bitmask[0]) == (b).bitmask[0]) && (((a).bitmask[1] & (b).bitmask[1]) == (b).bitmask[1]) && (((a).bitmask[2] & (b).bitmask[2]) == (b).bitmask[2]))


#define NDPI_BITMASK_ADD(a,b)   {(a).bitmask[0] |= (b).bitmask[0]; (a).bitmask[1] |= (b).bitmask[1]; (a).bitmask[2] |= (b).bitmask[2];}
#define NDPI_BITMASK_AND(a,b)   {(a).bitmask[0] &= (b).bitmask[0]; (a).bitmask[1] &= (b).bitmask[1]; (a).bitmask[2] &= (b).bitmask[2];}
#define NDPI_BITMASK_DEL(a,b)   {(a).bitmask[0] = (a).bitmask[0] & (~((b).bitmask[0])); (a).bitmask[1] = (a).bitmask[1] & ( ~((b).bitmask[1])); (a).bitmask[0] = (a).bitmask[0] & (~((b).bitmask[0]));}

#define NDPI_BITMASK_SET(a,b)   {(a).bitmask[0] = ((b).bitmask[0]); (a).bitmask[1] = (b).bitmask[1]; (a).bitmask[2] = (b).bitmask[2];}

#define NDPI_BITMASK_RESET(a)   {((a).bitmask[0]) = 0; ((a).bitmask[1]) = 0; ((a).bitmask[2]) = 0;}
#define NDPI_BITMASK_SET_ALL(a)   {((a).bitmask[0]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[1]) = 0xFFFFFFFFFFFFFFFFULL; ((a).bitmask[2]) = 0xFFFFFFFFFFFFFFFFULL;}

/* this is a very very tricky macro *g*,
  * the compiler will remove all shifts here if the protocol is static...
 */
#define NDPI_ADD_PROTOCOL_TO_BITMASK(bmask,value)         \
  {(bmask).bitmask[(value) >> 6] |= (((u64)1)<<((value) & 0x3F));}    \

#define NDPI_DEL_PROTOCOL_FROM_BITMASK(bmask,value)               \
  {(bmask).bitmask[(value) >> 6] = (bmask).bitmask[(value) >> 6] & (~(((u64)1)<<((value) & 0x3F)));}  \

#define NDPI_COMPARE_PROTOCOL_TO_BITMASK(bmask,value)         \
  ((bmask).bitmask[(value) >> 6] & (((u64)1)<<((value) & 0x3F)))      \


#define NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_STRING  "%llu , %llu , %llu"
#define NDPI_BITMASK_DEBUG_OUTPUT_BITMASK_VALUE(bm) (bm).bitmask[0] , (bm).bitmask[1] , (bm).bitmask[2]

#define NDPI_BITMASK_IS_ZERO(a) ( (a).bitmask[0] == 0 && (a).bitmask[1] == 0 && (a).bitmask[2] == 0)

#define NDPI_BITMASK_CONTAINS_NEGATED_BITMASK(a,b) ((((a).bitmask[0] & ~(b).bitmask[0]) == ~(b).bitmask[0]) && (((a).bitmask[1] & ~(b).bitmask[1]) == ~(b).bitmask[1]) && (((a).bitmask[2] & ~(b).bitmask[2]) == ~(b).bitmask[2]))


#endif

#define NDPI_PARSE_PACKET_LINE_INFO(ndpi_struct,packet)                        \
                        if (packet->packet_lines_parsed_complete != 1) {        \
                                ndpi_parse_packet_line_info(ndpi_struct);      \
                        }                                                       \

#ifdef __cplusplus
}
#endif
#endif
