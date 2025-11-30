#ifndef RED1_CRYPTO_H
#define RED1_CRYPTO_H


int encrypt_chunk_stride(const char *filepath, long start_offset, int chunks, long chunk_size, long skip_distance);
int decrypt_chunk_stride(const char *filepath, long start_offset, int chunks, long chunk_size, long skip_distance);

#endif