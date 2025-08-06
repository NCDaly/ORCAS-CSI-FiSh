#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include "orcas.h"
#include "csifish.h"
#include "stdint.h"
#include <time.h>

#define KEYS 1
#define SIGNATURES_PER_KEY 100

static inline
uint64_t rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((uint64_t)hi << 32) | lo;
}
#define TIC printf("\n"); uint64_t cl = rdtsc();
#define TOC(A) printf("%s cycles = %lu \n",#A ,rdtsc() - cl); cl = rdtsc();

int main(){

	clock_t t0;
	unsigned char *pk = aligned_alloc(64,PK_BYTES);
	unsigned char *sk = aligned_alloc(64,SK_BYTES);
	unsigned char *Y = aligned_alloc(64,STMT_BYTES);
	unsigned char *y = aligned_alloc(64,WIT_BYTES);

	printf("pk bytes : %ld\n", (long) PK_BYTES );
	printf("sk bytes : %ld\n", (long) SK_BYTES );
	printf("Y bytes : %ld\n", (long) STMT_BYTES );
	printf("y bytes : %ld\n", (long) WIT_BYTES );

	unsigned char message[1];
	message[0] = 42;
	unsigned char sig[SIG_BYTES+1];
	unsigned char psig[PSIG_BYTES+1];
	uint64_t sig_len;
	uint64_t psig_len;

	double keygenTime = 0;
	double signTime = 0;
	double verifyTime = 0;
	double rgenTime = 0;
	double presignTime = 0;
	double preverifyTime = 0;
	double adaptTime = 0;
	double extractTime = 0;
	
	uint64_t keygenCycles = 0;
	uint64_t signCycles = 0;
	uint64_t verifyCycles = 0;
	uint64_t rgenCycles = 0;
	uint64_t presignCycles = 0;
	uint64_t preverifyCycles = 0;
	
	uint64_t sig_size = 0;
	uint64_t sig_size_max = 0;
	uint64_t sig_size_min = 10000000;
	uint64_t psig_size = 0;
	uint64_t psig_size_max = 0;
	uint64_t psig_size_min = 10000000;
	
	uint64_t t;

	for(int i=0 ; i<KEYS; i++){
		printf("keygen #%d \n", i);
		t0 = clock();
		t = rdtsc();
		csifish_keygen(pk,sk);
		keygenCycles += rdtsc()-t;
		keygenTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;

		for(int j=0; j<SIGNATURES_PER_KEY; j++){
			printf("(pre-)signature #%d for key %d \n", j , i );

			// CSI-FiSh at bat

			t0 = clock();
			t = rdtsc();
			csifish_sign(sk,message,1,sig,&sig_len);
			signCycles += rdtsc()-t;
			signTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;
			sig_size += sig_len;

			sig_size_max = ( sig_len > sig_size_max ? sig_len : sig_size_max );
			sig_size_min = ( sig_len > sig_size_min ? sig_size_min : sig_len );

			sig[sig_len] = 0;

			t0 = clock();
			t = rdtsc();
			int ver = csifish_verify(pk,message,1,sig, sig_len);
			verifyCycles += rdtsc()-t;
			verifyTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;

			if(ver <0){
				printf("Signature invalid! \n");
			}

			// ORCAS at bat

			t0 = clock();
			t = rdtsc();
			orcas_rgen(Y, y);
			rgenCycles += rdtsc()-t;
			rgenTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;

			t0 = clock();
			t = rdtsc();
			orcas_presign(sk,m,1,Y,psig,&psig_len);
			presignCycles += rdtsc()-t;
			presignTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;
			psig_size += psig_len;

			psig_size_max = ( psig_len > psig_size_max ? psig_len : psig_size_max );
			psig_size_min = ( psig_len > psig_size_min ? psig_size_min : psig_len );

			psig[psig_len] = 0;

			t0 = clock();
			t = rdtsc();
			int pver = orcas_preverify(pk,message,1,Y,psig,psig_len);
			preverifyCycles += rdtsc()-t;
			preverifyTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;

			if(pver <0){
				printf("Pre-signature invalid! \n");
			}

			t0 = clock();
			t = rdtsc();
			orcas_adapt(psig, psig_len, y, sig, &sig_len);
			adaptCycles += rdtsc()-t;
			adaptTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;

			t0 = clock();
			t = rdtsc();
			orcas_extract(psig, psig_len, sig, sig_len, y);
			extractCycles += rdtsc()-t;
			extractTime += 1000. * (clock() - t0) / CLOCKS_PER_SEC;

		}
	}

	printf("average sig bytes: %ld\n", sig_size/KEYS/SIGNATURES_PER_KEY); 
	printf("maximum sig bytes: %ld\n", sig_size_max); 
	printf("minimum sig bytes: %ld\n\n", sig_size_min); 

	printf("average psig bytes: %ld\n", psig_size/KEYS/SIGNATURES_PER_KEY); 
	printf("maximum psig bytes: %ld\n", psig_size_max); 
	printf("minimum psig bytes: %ld\n\n", psig_size_min); 

	printf("keygen cycles :           %lu \n", keygenCycles/KEYS );
	printf("signing cycles :          %lu \n", signCycles/KEYS/SIGNATURES_PER_KEY );
	printf("verification cycles :     %lu \n", verifyCycles/KEYS/SIGNATURES_PER_KEY );
	printf("rgen cycles :             %lu \n", rgenCycles/KEYS/SIGNATURES_PER_KEY );
	printf("pre-signing cycles :      %lu \n", presignCycles/KEYS/SIGNATURES_PER_KEY );
	printf("pre-verification cycles : %lu \n", preverifyCycles/KEYS/SIGNATURES_PER_KEY );
	printf("adapting cycles :         %lu \n", adaptCycles/KEYS/SIGNATURES_PER_KEY );
	printf("extracting cycles :       %lu \n\n", extractCycles/KEYS/SIGNATURES_PER_KEY );

	printf("keygen time :           %lf ms \n", keygenTime/KEYS );
	printf("signing time :          %lf ms \n", signTime/KEYS/SIGNATURES_PER_KEY );
	printf("verification time :     %lf ms \n", verifyTime/KEYS/SIGNATURES_PER_KEY );
	printf("rgen time :             %lf ms \n", rgenTime/KEYS/SIGNATURES_PER_KEY );
	printf("pre-signing time :      %lf ms \n", presignTime/KEYS/SIGNATURES_PER_KEY );
	printf("pre-verification time : %lf ms \n", preverifyTime/KEYS/SIGNATURES_PER_KEY );
	printf("adapting time :         %lf ms \n", adaptTime/KEYS/SIGNATURES_PER_KEY );
	printf("extracting time :       %lf ms \n", extractTime/KEYS/SIGNATURES_PER_KEY );

	free(pk);
	free(sk);
}
