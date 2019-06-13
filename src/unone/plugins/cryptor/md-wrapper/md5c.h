//See internet RFC 1321, "The MD5 Message-Digest Algorithm"

/* Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.

License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.

License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.

RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.

These notices must be retained in any copies of any part of this
documentation and/or software.
 */

/* MD5 context. */

#ifndef _MD5CONTEXT_H
#define _MD5CONTEXT_H
#include <Windows.h>

#ifndef _MD5_GLOBAL_H
#define _MD5_GLOBAL_H

/* PROTOTYPES should be set to one if and only if the compiler supports
  function argument prototyping.
The following makes PROTOTYPES default to 0 if it has not already

  been defined with C compiler flags.
 */
#ifndef PROTOTYPES
#define PROTOTYPES 1
#endif

/* POINTER defines a generic pointer type */
typedef unsigned char *POINTER;

/* UINT2 defines a two byte word */
typedef unsigned short int UINT2;

/* UINT4 defines a four byte word */
typedef unsigned long int UINT4;

/* PROTO_LIST is defined depending on how PROTOTYPES is defined above.
If using PROTOTYPES, then PROTO_LIST returns the list, otherwise it
  returns an empty list.
 */
#if PROTOTYPES
#define PROTO_LIST(list) list
#else
#define PROTO_LIST(list) ()
#endif

#endif

typedef struct {
	UINT state[4];                                   /* state (ABCD) */
	UINT count[2];        /* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];                         /* input buffer */
} MD5_CTX, *PMD5_CTX;

#ifdef __cplusplus	//added by Jim Howard so that these functions can be called from c++
extern "C" 
{
#endif
	void MD5Init PROTO_LIST ((MD5_CTX *));
	void MD5Update PROTO_LIST ((MD5_CTX *,  unsigned char *, unsigned int));
	void MD5Final PROTO_LIST ((unsigned char [16], MD5_CTX *));
#ifdef __cplusplus
}
#endif

#endif