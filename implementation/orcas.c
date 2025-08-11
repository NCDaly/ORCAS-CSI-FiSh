#include "orcas.h"

void orcas_rgen(uint *stmt, mpz_t wit) {
	init_classgroup();
  
	// pick random seed
	unsigned char seed[SEED_BYTES];
	RAND_bytes(seed, SEED_BYTES);

	// pick witness & generate statement
	private_key vec;
	public_key out;
	sample_mod_cn_with_seed(seed, wit);
	mod_cn_2_vec(wit, vec.e);
  
	// perform action
	action(&out, &base, &vec);
	
	// decode endpoint
	fp_dec(stmt,&out.A);
	
	clear_classgroup();
}

int orcas_presign(const unsigned char *sk,const unsigned char *m, uint64_t mlen, const uint *stmt, unsigned char *psig, uint64_t *psig_len) {
	init_classgroup();
  
	// hash the message
	unsigned char m_hash[HASH_BYTES];
	HASH(m,mlen,m_hash);
  
	// pick random seeds
	unsigned char seeds[SEED_BYTES*ROUNDS];
	RAND_bytes(seeds,SEED_BYTES*ROUNDS);

	// pick round to adapt
	int target = 0; //randrange(0, ROUNDS);
  
	// compute curves
	mpz_t r[ROUNDS];
	uint curves[ROUNDS] = {{{0}}};
	for(int i=0 ; i<ROUNDS; i++){
		private_key priv;
    
		// sample mod class number and convert to vector
		mpz_init(r[i]);
		sample_mod_cn_with_seed(seeds + i*SEED_BYTES,r[i]);
		mod_cn_2_vec(r[i],priv.e);
    
		// compute E_o * vec (Y * vec in target round)
		public_key start,end;
		if (i == target) {
			fp_enc(&start.A, stmt);
		} else {
			start = base;
		}
		
		action(&end, &start, &priv);      
    
		// convert to uint64_t's
		fp_dec(&curves[i], &end.A);
	}

	// shuffle & repeat until we get an acceptable challenge
	unsigned char master_hash[HASH_BYTES];
	uint32_t challenges_index[ROUNDS];
	uint8_t challenges_sign[ROUNDS];
  
	unsigned char randomness[SEED_BYTES + 4] = {0};
	uint32_t *attempts = (uint32_t *) (randomness + SEED_BYTES);
	RAND_bytes(randomness, SEED_BYTES);
	while (1) {
		// hash curves
		unsigned char curve_hash[HASH_BYTES];
		HASH((unsigned char *) curves, sizeof(uint[ROUNDS]), curve_hash);
		
		// compute master hash
		unsigned char in_buf[2*HASH_BYTES];
		memcpy(in_buf,m_hash,HASH_BYTES);
		memcpy(in_buf + HASH_BYTES, curve_hash, HASH_BYTES);
		HASH(in_buf,2*HASH_BYTES, master_hash);
		
		// get challenges
		get_challenges(master_hash,challenges_index,challenges_sign);
		if (challenges_index[target] == PKS) {
			break;
		}
		
		// shuffle if we didn't like the challenge
		unsigned char perm_seed[SEED_BYTES];
		int perm[ROUNDS];
		EXPAND(randomness, SEED_BYTES + 4, perm_seed, SEED_BYTES);
		perm_with_seed(perm_seed, perm, ROUNDS);
		for (int i = 0; i < ROUNDS - 1; i++) {
			int j = perm[i];
			swap_elems((unsigned char *) curves, i, j, sizeof(uint));
			swap_elems((unsigned char *) r, i, j, sizeof(mpz_t));
			swap_index(&target, i, j);
		}

		// count attempts and abort if needed
		if (++(*attempts) >= MAX_ATTEMPTS) {
			target = ROUNDS;
			break;
		}
	}

	// copy target and hash to pre-signature
	psig[0] = (unsigned char) target;
	memcpy(PSIG_HASH(psig),master_hash,HASH_BYTES);

	// generate seeds
	unsigned char *sk_seeds = malloc(SEED_BYTES*PKS);
	EXPAND(sk,SEED_BYTES,sk_seeds,SEED_BYTES*PKS);

	// generate secrets mod p
	unsigned char *indices = calloc(1,PKS);
	(void) indices;
	mpz_t s[ROUNDS];
	for(int i=0; i<ROUNDS; i++){
		// only mix in a secret key if challenge < PKS
		if (challenges_index[i] < PKS) {
			indices[challenges_index[i]] = 1;
			mpz_init(s[i]);
			sample_mod_cn_with_seed(sk_seeds + challenges_index[i]*SEED_BYTES,s[i]);
			if(challenges_sign[i]){
				mpz_mul_si(s[i],s[i],-1);
			}
			mpz_sub(r[i],s[i],r[i]);
			mpz_clear(s[i]);
		} else {
			mpz_sub(r[i],cn,r[i]);	  
		}
		mpz_fdiv_r(r[i],r[i],cn);

		// silly trick to force export to have 33 bytes
		mpz_add(r[i],r[i],cn);

		mpz_export(PSIG_RESPONSES(psig) + 33*i, NULL, 1, 1, 1, 0, r[i]);

		mpz_clear(r[i]);
	}
  
	// update pre-signature length
	(*psig_len) = PSIG_BYTES;
  
	clear_classgroup();
	free(indices);
	free(sk_seeds);

	return (int) *attempts;
}

int orcas_preverify(const unsigned char *pk, const unsigned char *m, uint64_t mlen, const uint *stmt, const unsigned char *psig, uint64_t psig_len) {
	// reject immediately if target round is invalid
	int target = (int) psig[0];
	if (target == ROUNDS) {
		return -3;
	}
  
	init_classgroup();
	(void) psig_len;
  
	// hash the message
	unsigned char m_hash[HASH_BYTES];
	HASH(m,mlen,m_hash);

	// get challenges
	uint32_t challenges_index[ROUNDS];
	uint8_t  challenges_sign[ROUNDS];
	get_challenges(PSIG_HASH(psig),challenges_index,challenges_sign);

	fp minus_one;
	fp_sub3(&minus_one, &fp_0, &fp_1);
  
	uint  curves[ROUNDS];
	uint* pkcurves = (uint*) PK_CURVES(pk);
	for(int i=0; i<ROUNDS; i++){
		// encode starting point
		public_key start,end;
		if (challenges_index[i] < PKS) {
			fp_enc(&(start.A), &pkcurves[challenges_index[i]]);
			if(challenges_sign[i]){
				fp_mul2(&start.A,&minus_one);
			}
		} else if (i == target) {
			fp_enc(&start.A, stmt);
		} else {
			start = base;
		}

		// decode path
		mpz_t x;
		mpz_init(x);
		private_key path;
		mpz_import(x,33,1,1,1,0,PSIG_RESPONSES(psig)+33*i);
		mpz_sub(x,x,cn);
		mod_cn_2_vec(x,path.e);
		mpz_clear(x);
    
		// flip vector
		for(int j=0; j<NUM_PRIMES; j++){
			path.e[j] = -path.e[j];
		}
    
		// perform action
		action(&end,&start,&path);
    
		// decode endpoint
		fp_dec(&curves[i],&end.A);
	}
  
	clear_classgroup();
  
	// challenge for target round should = PKS
	if (challenges_index[target] < PKS) {
		return -2;
	}
  
	// hash curves
	unsigned char curve_hash[HASH_BYTES];
	HASH((unsigned char *) curves, sizeof(uint[ROUNDS]), curve_hash);
  
	// compute master hash
	unsigned char in_buf[2*HASH_BYTES], master_hash[HASH_BYTES];
	memcpy(in_buf,m_hash,HASH_BYTES);
	memcpy(in_buf + HASH_BYTES, curve_hash, HASH_BYTES);
	HASH(in_buf,2*HASH_BYTES, master_hash);
  
	// compare master_hash with signature_hash
	if(memcmp(master_hash,PSIG_HASH(psig),HASH_BYTES)){
		return -1;
	}
  
	return 1;
}

void orcas_adapt(const unsigned char *psig, uint64_t psig_len, mpz_t wit, unsigned char *sig, uint64_t *sig_len) {
	// identify round to adapt
	int target = (int) psig[0];

	// copy pre-signature
	memcpy(sig, PSIG_HASH(psig), SIG_BYTES);
	*sig_len = SIG_BYTES;
	(void) psig_len;

	init_classgroup();

	// adapt the target index
	mpz_t x;
	mpz_init(x);

	mpz_import(x,33,1,1,1,0,PSIG_RESPONSES(psig)+33*target);
	mpz_sub(x,x,wit);
	mpz_fdiv_r(x,x,cn);
	mpz_add(x,x,cn);
	mpz_export(SIG_RESPONSES(sig) + 33*target, NULL, 1, 1, 1, 0, x);

	mpz_clear(x);
	clear_classgroup();
}

int orcas_extract(const unsigned char *psig, uint64_t psig_len, const unsigned char *sig, uint64_t sig_len, mpz_t wit) {  
	if(memcmp(PSIG_HASH(psig),SIG_HASH(sig),HASH_BYTES)){
		return -1;
	}

	(void) psig_len;
	(void) sig_len;
  
	init_classgroup();

	unsigned char target = psig[0];
	mpz_t x, px;
	mpz_init(x);
	mpz_init(px);
  
	mpz_import(px,33,1,1,1,0,PSIG_RESPONSES(psig)+33*target);
	mpz_import(x,33,1,1,1,0,SIG_RESPONSES(sig)+33*target);
	mpz_sub(wit,px,x);
	mpz_fdiv_r(wit,wit,cn);
  
	mpz_clear(x);
	mpz_clear(px);
	clear_classgroup();

	return 1;
}
