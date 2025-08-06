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

void orcas_rgen(unsigned char *Y, unsigned char *y);
void orcas_presign(const unsigned char *sk,const unsigned char *m, uint64_t mlen, const unsigned char *Y, unsigned char *psig, uint64_t *psig_len);
int orcas_preverify(const unsigned char *pk, const unsigned char *m, uint64_t mlen, const unsigned char *Y, const unsigned char *psig, uint64_t psig_len);
void orcas_adapt(const unsigned *psig, uint64_t psig_len, const unsigned char *y, unsigned char *sig, uint64_t *sig_len);
void orcas_extract(const unsigned *psig, uint64_t psig_len, const unsigned *sig, uint64_t sig_len, unsigned char *y);

#endif
