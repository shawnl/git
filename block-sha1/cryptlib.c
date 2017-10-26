/*
 * Copyright 1998-2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/safestack.h>

#if     defined(__i386)   || defined(__i386__)   || defined(_M_IX86) || \
        defined(__x86_64) || defined(__x86_64__) || \
        defined(_M_AMD64) || defined(_M_X64)

extern unsigned int OPENSSL_ia32cap_P[4];

# if defined(OPENSSL_CPUID_OBJ) && !defined(OPENSSL_NO_ASM) && !defined(I386_ONLY)
#include <stdio.h>
#  define OPENSSL_CPUID_SETUP
typedef uint64_t IA32CAP;
void OPENSSL_cpuid_setup(void)
{
    static int trigger = 0;
    IA32CAP OPENSSL_ia32_cpuid(unsigned int *);
    IA32CAP vec;
    char *env;

    if (trigger)
        return;

    trigger = 1;
    if ((env = getenv("OPENSSL_ia32cap"))) {
        int off = (env[0] == '~') ? 1 : 0;
#  if defined(_WIN32)
        if (!sscanf(env + off, "%I64i", &vec))
            vec = strtoul(env + off, NULL, 0);
#  else
        if (!sscanf(env + off, "%lli", (long long *)&vec))
            vec = strtoul(env + off, NULL, 0);
#  endif
        if (off) {
            IA32CAP mask = vec;
            vec = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P) & ~mask;
            if (mask & (1<<24)) {
                /*
                 * User disables FXSR bit, mask even other capabilities
                 * that operate exclusively on XMM, so we don't have to
                 * double-check all the time. We mask PCLMULQDQ, AMD XOP,
                 * AES-NI and AVX. Formally speaking we don't have to
                 * do it in x86_64 case, but we can safely assume that
                 * x86_64 users won't actually flip this flag.
                 */
                vec &= ~((IA32CAP)(1<<1|1<<11|1<<25|1<<28) << 32);
            }
        } else if (env[0] == ':') {
            vec = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P);
        }

        if ((env = strchr(env, ':'))) {
            unsigned int vecx;
            env++;
            off = (env[0] == '~') ? 1 : 0;
            vecx = strtoul(env + off, NULL, 0);
            if (off)
                OPENSSL_ia32cap_P[2] &= ~vecx;
            else
                OPENSSL_ia32cap_P[2] = vecx;
        } else {
            OPENSSL_ia32cap_P[2] = 0;
        }
    } else {
        vec = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P);
    }

    /*
     * |(1<<10) sets a reserved bit to signal that variable
     * was initialized already... This is to avoid interference
     * with cpuid snippets in ELF .init segment.
     */
    OPENSSL_ia32cap_P[0] = (unsigned int)vec | (1 << 10);
    OPENSSL_ia32cap_P[1] = (unsigned int)(vec >> 32);
}
# else
unsigned int OPENSSL_ia32cap_P[4];
# endif
#endif
int OPENSSL_NONPIC_relocated = 0;
#if !defined(OPENSSL_CPUID_SETUP) && !defined(OPENSSL_CPUID_OBJ)
void OPENSSL_cpuid_setup(void)
{
}
#endif
