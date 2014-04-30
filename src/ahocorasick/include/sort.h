/*
 * A fast, small, non-recursive O(nlog n) sort for the Linux kernel
 *
 * Jan 23 2005  Matt Mackall <mpm@selenic.com>
 */

/* This is a function ported from the Linux kernel lib/sort.c */

void sort(void *base, size_t num, size_t len,
	  int (*cmp_func)(const void *, const void *),
	  void (*swap_func)(void *, void *, int size));
  
