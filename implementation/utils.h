#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include "stdint.h"
#include "params.h"
#include "parameters.h"
#include "rng.h"
#include <openssl/rand.h>

void print_uint(uint x);
int randrange_with_seed(const unsigned char *seed, int min, int max);
int randrange(int min, int max);
void permute_array_with_seed(const unsigned char *seed, unsigned char *arr, uint64_t elem_size, int  num_elems);
void permute_array(unsigned char *arr, uint64_t elem_size, int num_elems);
void permute_index_with_seed(const unsigned char *seed, int *index, int num_elems);
void permute_index(int *index, int num_elems);

void perm_with_seed(const unsigned char *seed, int *perm, int num_elems);
void swap_elems(unsigned char *arr, int i, int j, uint64_t elem_size);
void swap_index(int *index, int i, int j);

#endif
