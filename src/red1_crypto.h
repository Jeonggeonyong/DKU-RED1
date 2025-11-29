#ifndef RED1_CRYPTO_H
#define RED1_CRYPTO_H


int encrypt_chunk_range(const char *filepath, long start_offset, int chunks_to_write);
int decrypt_chunk_range(const char *filepath, long start_offset, int chunks_to_write);


#endif