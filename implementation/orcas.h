#ifndef ORCAS_H
#define ORCAS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "csifish.h"
#include "csidh.h"
#include "merkletree.h"
#include "stdint.h"
#include "parameters.h"
#include "classgroup.h"
#include "fp.h"
#include "gmp.h"

#ifdef MERKLEIZE_PK
#error "ORCAS does not (yet?) support Merkle CSI-FiSh."
#endif

#define MAX_ATTEMPTS (1<<16)
#define PSIG_HASH(psig) (psig + 1)
#define PSIG_RESPONSES(psig) (PSIG_HASH(psig) + HASH_BYTES)
#define PSIG_BYTES (PSIG_RESPONSES(0) + 33*ROUNDS)
#define STMT_BYTES (sizeof(uint))
#define WIT_BYTES 33

void orcas_rgen(uint *stmt, mpz_t wit);
int orcas_presign(const unsigned char *sk, const unsigned char *m, uint64_t mlen, const uint *stmt, unsigned char *psig, uint64_t *psig_len);
int orcas_preverify(const unsigned char *pk, const unsigned char *m, uint64_t mlen, const uint *stmt, const unsigned char *psig, uint64_t psig_len);
void orcas_adapt(const unsigned char *psig, uint64_t psig_len, mpz_t wit, unsigned char *sig, uint64_t *sig_len);
int orcas_extract(const unsigned char *psig, uint64_t psig_len, const unsigned char *sig, uint64_t sig_len, mpz_t wit);

#endif
