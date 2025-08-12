#include "utils.h"

void print_uint(uint x){
	for(int i=0 ; i<LIMBS; i++){
		printf("%lu ", x.c[i] );
	}
	printf("\n");
}

int randrange_with_seed(const unsigned char *seed, int min, int max) {
	// handle bad inputs
	if (min >= max) {
		return min;
	}

	// sample uniformly from [min, max)
	uint32_t rand;
	uint32_t range = max - min;
	uint32_t max_rand = 1<<30;
	uint32_t bad_rand = max_rand - (max_rand % range);
	unsigned char in_buf[SEED_BYTES+1];
	memcpy(in_buf, seed, SEED_BYTES);
	in_buf[SEED_BYTES] = 0;
  
	while(1){
		// get randomness in [0, max_rand)
		EXPAND(in_buf, SEED_BYTES+1, (unsigned char *) &rand, 4);
		rand &= max_rand - 1;
		in_buf[SEED_BYTES]++;

		// use randomness in [0, bad_rand)
		if (rand < bad_rand) {
			return min + (int) (rand % range);
		}
	}
}

int randrange(int min, int max) {
	// pick random seed
	unsigned char seed[SEED_BYTES];
	RAND_bytes(seed,SEED_BYTES);
  
	// sample with seed
	return randrange_with_seed(seed, min, max);
}

void perm_with_seed(const unsigned char *seed, int *perm, int num_elems) {
	// based on Durstenfeld's version of the Fisher-Yates shuffle
	unsigned char seeds[SEED_BYTES*(num_elems-1)];
	EXPAND(seed, SEED_BYTES, seeds, SEED_BYTES);
	for (int i = 0; i < num_elems-1; i++) {
		perm[i] = randrange_with_seed(&seeds[SEED_BYTES*i], i, num_elems);
	}
}

void swap_elems(unsigned char *arr, int i, int j, uint64_t elem_size) {
	unsigned char tmp[elem_size];
	memcpy(tmp, &arr[elem_size*i], elem_size);
	memcpy(&arr[elem_size*i], &arr[elem_size*j], elem_size);
	memcpy(&arr[elem_size*j], tmp, elem_size);
}

void swap_index(int *index, int i, int j) {
	if (*index == i) {
		*index = j;
	} else if (*index == j) {
		*index = i;
	}
}
