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
  action(&out, &base, &vec);
  
  // convert to uint64_t
  fp_dec(stmt, &(out.A));
  
  clear_classgroup();
}

int randrange_with_seed(const unsigned char *seed, int min, int max) {
  // just return min for bad inputs
  if (min >= max) {
    return min;
  }

  // sample uniformly from [min, max)
  uint32_t rand;
  uint32_t range = max - min;
  uint32_t bad_rand = range * (((uint32_t) 1<<30) / range);
  unsigned char in_buf[SEED_BYTES+1];
  memcpy(in_buf, seed, SEED_BYTES);
  in_buf[SEED_BYTES] = 0;
  
  while(1){
    // get randomness in [0, 2^30)
    EXPAND(in_buf, SEED_BYTES+1, (unsigned char *) &rand, 4);
    rand &= ((uint32_t) 1<<30)-1;
    in_buf[SEED_BYTES]++;

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

void shuffle_curves_with_seed(const unsigned char *seed, unsigned char *target, uint *curves) {
  // using Durstenfeld's version of the Fisher-Yates shuffle
  // (plus some extra bookkeeping to track the target round)
  unsigned char seeds[SEED_BYTES*(ROUNDS-1)];
  EXPAND(seed, SEED_BYTES, seeds, SEED_BYTES);
  int swaps[ROUNDS-1];

  // permute the curves, keeping track of which swaps we apply
  for (int i = 0; i <= ROUNDS - 2; i++) {
    // pick random index i <= j < ROUNDS to swap with i
    swaps[i] = randrange_with_seed(seeds+SEED_BYTES*i, i, ROUNDS);
    
    // apply permutation (i, j)
    uint tmp = curves[i];
    curves[i] = curves[swaps[i]];
    curves[swaps[i]] = tmp;
  }

  // apply INVERSE permutation to target (i.e. swaps in reverse order)
  for (int i = ROUNDS - 2; i >= 0; i--) {
    if ((int) *target == i || (int) *target == swaps[i]) {
      *target = (unsigned char) ((int) *target == i ? swaps[i] : i);
    }
  }
}

void shuffle_curves(unsigned char *target, uint *curves) {
  // pick random seed
  unsigned char seed[SEED_BYTES];
  RAND_bytes(seed,SEED_BYTES);

  // shuffle with seed
  shuffle_curves_with_seed(seed, target, curves);
}

void orcas_presign(const unsigned char *sk,const unsigned char *m, uint64_t mlen, const uint *stmt, unsigned char *psig, uint64_t *psig_len) {
  init_classgroup();
  
  // hash the message
  unsigned char m_hash[HASH_BYTES];
  HASH(m,mlen,m_hash);
  
  // pick random seeds
  unsigned char seeds[SEED_BYTES*ROUNDS];
  RAND_bytes(seeds,SEED_BYTES*ROUNDS);

  // pick target round
  unsigned char target = randrange(0, ROUNDS);
  
  // compute curves
  mpz_t r[ROUNDS];
  uint curves[ROUNDS] = {{{0}}};
  for(int k=0 ; k<ROUNDS; k++){
    private_key priv;
    
    // sample mod class number and convert to vector
    mpz_init(r[k]);
    sample_mod_cn_with_seed(seeds + k*SEED_BYTES,r[k]);
    mod_cn_2_vec(r[k],priv.e);
    
    // compute E_o * vec (Y * vec in target round)
    public_key out;
    if (k == target) {
      public_key start;
      fp_enc(&start.A, stmt);
      action(&out, &start, &priv);      
    } else {
      action(&out, &base, &priv);
    }
    
    // convert to uint64_t's
    fp_dec(&curves[k], &out.A);
  }

  // shuffle & repeat until we get an acceptable challenge
  unsigned char master_hash[HASH_BYTES];
  uint32_t challenges_index[ROUNDS];
  uint8_t challenges_sign[ROUNDS];
  
  unsigned char randomness[SEED_BYTES + 4] = {0};
  uint32_t *shuffles = (uint32_t *) (randomness + SEED_BYTES);
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
    if (challenges_index[target] == 0) {
      break;
    }

    // shuffle and repeat
    unsigned char shuffle_seed[SEED_BYTES];
    EXPAND(randomness, SEED_BYTES + 8, shuffle_seed, SEED_BYTES);
    shuffle_curves_with_seed(shuffle_seed, &target, curves);
    if (++(*shuffles) >= MAX_SHUFFLES) {
      target = ROUNDS;
      break;
    }
  }

  printf("target : %d \n", (int) target);
  for (int i = 0; i < ROUNDS; i++) {
    printf("curve %d : ", i);
    print_uint(curves[i]);
  }

  // copy target and hash to pre-signature
  psig[0] = target;
  memcpy(PSIG_HASH(psig),master_hash,HASH_BYTES);
  
  // generate seeds
  unsigned char *sk_seeds = malloc(SEED_BYTES*PKS);
  EXPAND(sk,SEED_BYTES,sk_seeds,SEED_BYTES*PKS);
  
  // generate secrets mod p
  unsigned char *indices = calloc(1,PKS);
  (void) indices;
  mpz_t s[ROUNDS];
  for(int i=0; i<ROUNDS; i++){
    indices[challenges_index[i]] = 1;
    mpz_init(s[i]);
    sample_mod_cn_with_seed(sk_seeds + challenges_index[i]*SEED_BYTES ,s[i]);
    if(challenges_sign[i]){
      mpz_mul_si(s[i],s[i],-1);
    }
    mpz_sub(r[i],s[i],r[i]);
    mpz_fdiv_r(r[i],r[i],cn);
    
    // silly trick to force export to have 33 bytes
    mpz_add(r[i],r[i],cn);
    
    mpz_export(PSIG_RESPONSES(psig) + 33*i, NULL, 1, 1, 1, 0, r[i]);
    
    mpz_clear(s[i]);
    mpz_clear(r[i]);
  }
  
  // update pre-signature length
  (*psig_len) = PSIG_BYTES;
  
  clear_classgroup();
  free(indices);
  free(sk_seeds);
}

int orcas_preverify(const unsigned char *pk, const unsigned char *m, uint64_t mlen, const uint *stmt, const unsigned char *psig, uint64_t psig_len) {
  // reject immediately if target round is invalid
  unsigned char target = psig[0];
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
    fp_enc(&(start.A), &pkcurves[challenges_index[i]]);
    
    if(challenges_sign[i]){
      fp_mul2(&start.A,&minus_one);
    }
    
    if (i == target) {
      fp_enc(&start.A, stmt);
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
  
  printf("target : %d \n", (int) target);
  for (int i = 0; i < ROUNDS; i++) {
    printf("curve %d : ", i);
    print_uint(curves[i]);
  }

  clear_classgroup();
  
  // challenge for target round should be 0
  if (challenges_index[target] != 0) {
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
  unsigned char target = psig[0];
  mpz_t x;
  mpz_init(x);
  memcpy(sig, PSIG_HASH(psig), SIG_BYTES);
  *sig_len = SIG_BYTES;
  (void) psig_len;

  // adapt the target index
  mpz_import(x,33,1,1,1,0,PSIG_RESPONSES(psig)+33*target);
  mpz_add(x,x,wit);
  mpz_fdiv_r(x,x,cn);
  mpz_add(x,x,cn);
  mpz_export(SIG_RESPONSES(sig) + 33*target, NULL, 1, 1, 1, 0, x);
  
  mpz_clear(x);
}

int orcas_extract(const unsigned char *psig, uint64_t psig_len, const unsigned char *sig, uint64_t sig_len, mpz_t wit) {  
  if(memcmp(PSIG_HASH(psig),SIG_HASH(sig),HASH_BYTES)){
    return -1;
  }

  (void) psig_len;
  (void) sig_len;
  
  unsigned char target = psig[0];
  mpz_t x, px;
  mpz_init(x);
  mpz_init(px);
  
  mpz_import(px,33,1,1,1,0,PSIG_RESPONSES(psig)+33*target);
  mpz_import(x,33,1,1,1,0,SIG_RESPONSES(sig)+33*target);
  mpz_sub(wit,x,px);
  mpz_fdiv_r(wit,wit,cn);
  
  mpz_clear(x);
  mpz_clear(px);

  return 1;
}
