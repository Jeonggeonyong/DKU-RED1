#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>     // usleep, fsync
#include <stdint.h>     // uint64_t
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <arpa/inet.h> 
#include <endian.h>     // be64toh, htobe64 (리눅스 표준)

// main.c와 동일하게 맞춤 (필요시 main.c의 define을 따라감)
#ifndef CHUNK_SIZE
#define CHUNK_SIZE (128 * 1024)
#endif

// 0.12초 (속도가 너무 느리면 50000 등으로 줄여서 튜닝 가능)
#define WRITE_DELAY_US 120000 

// 키 (고정)
static const unsigned char aes_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

void handle_openssl_errors(void) {
    ERR_print_errors_fp(stderr);
}

// 경로 기반 해시 IV 생성 (기존 로직 유지)
void generate_iv_from_path(const char *filepath, unsigned char *iv_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, filepath, strlen(filepath));
    SHA256_Final(hash, &sha256);
    memcpy(iv_out, hash, 16);
}

// [추가] 특정 오프셋에 맞는 AES-CTR IV 계산 함수
// (루프 안에서 반복 호출하기 위해 분리함)
void calculate_chunk_iv(const char *filepath, long offset, unsigned char *iv_out) {
    // 1. 기본 해시 IV 생성
    generate_iv_from_path(filepath, iv_out);

    // 2. 오프셋에 따른 블록 카운터 계산 (AES 블록 16바이트)
    uint64_t block_counter = offset / 16;
    
    // 3. IV 뒤쪽 8바이트에 카운터 반영
    if (block_counter > 0) {
        uint64_t *counter_ptr = (uint64_t*)(iv_out + 8);
        uint64_t host_counter = be64toh(*counter_ptr);
        host_counter += block_counter;
        *counter_ptr = htobe64(host_counter);
    }
}

/**
 * [수정됨] Stride 지원 Worker
 * @param skip_distance: 한 번 쓰고 나서 건너뛸 거리 (main.c에서 전달받음)
 */
static int process_chunk_stride(const char *filepath, long start_offset, int chunks_to_write, long stride_chunk_size, long skip_distance, int mode) {
    FILE *fp = fopen(filepath, "r+b");
    if (!fp) {
        perror("fopen (r+b)");
        return -1; 
    }

    // 메모리 할당 (기존 유지)
    unsigned char *in_buf = malloc(stride_chunk_size);
    unsigned char *out_buf = malloc(stride_chunk_size + EVP_MAX_BLOCK_LENGTH);

    if (!in_buf || !out_buf) {
        perror("malloc failed");
        if (in_buf) free(in_buf);
        if (out_buf) free(out_buf);
        fclose(fp);
        return -1;
    }

    // Context 생성
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { 
        free(in_buf); free(out_buf); fclose(fp);
        return -1; 
    }

    int ret = 0; // 성공 기본값
    long current_pos = start_offset; // 현재 파일 포인터 위치
    int out_len;
    unsigned char current_iv[16]; // 매 청크마다 계산될 IV

    // =================================================================
    // [핵심 변경] 루프 구조: Init -> Update -> Write -> Skip -> Sleep
    // =================================================================
    for (int i = 0; i < chunks_to_write; i++) {
        
        // 1. 읽기 위치로 이동
        if (fseek(fp, current_pos, SEEK_SET) != 0) break; // 파일 끝 등 에러

        // 2. 읽기
        int read_len = fread(in_buf, 1, stride_chunk_size, fp);
        if (read_len <= 0) break; 

        // 3. [중요] 현재 위치(current_pos)에 맞는 IV 계산
        // 건너뛰기를 하면 오프셋이 불연속적이므로, 매번 다시 초기화해야 함
        calculate_chunk_iv(filepath, current_pos, current_iv);

        // 4. 암/복호화 초기화 (Init)
        if (mode == 0) { // ENCRYPT
            if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, aes_key, current_iv)) {
                handle_openssl_errors(); ret = -1; break;
            }
            if (1 != EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, read_len)) {
                handle_openssl_errors(); ret = -1; break;
            }
        } else { // DECRYPT
            if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, aes_key, current_iv)) {
                handle_openssl_errors(); ret = -1; break;
            }
            if (1 != EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, read_len)) {
                handle_openssl_errors(); ret = -1; break;
            }
        }

        // 5. [기존 유지] 샌드위치 기법 (Entropy Reduction)
        int stripe_size = 16; 
        for (int k = 0; k < out_len; k += (stripe_size * 2)) {
            int skip_offset = k + stripe_size;
            if (skip_offset < out_len) {
                int copy_len = stripe_size;
                if (skip_offset + copy_len > out_len) {
                    copy_len = out_len - skip_offset;
                }
                memcpy(out_buf + skip_offset, in_buf + skip_offset, copy_len);
            }
        }

        // 6. 쓰기 (읽었던 위치에 그대로 덮어쓰기)
        fseek(fp, current_pos, SEEK_SET);
        fwrite(out_buf, 1, out_len, fp);
        fflush(fp); 

        // 7. [핵심] 다음 위치 계산 (Stride 적용)
        // 읽은 만큼 + 건너뛸 만큼 점프
        current_pos += read_len + skip_distance;

        // 8. 딜레이
        usleep(WRITE_DELAY_US);
    }
    
    // 루프 종료 후 정리
    EVP_CIPHER_CTX_free(ctx);
    free(in_buf);
    free(out_buf);
    fsync(fileno(fp));
    fclose(fp);
    return ret;
}

// === main.c와 호환되는 Wrapper 함수 ===

// main.c에서 호출하는 이름: encrypt_chunk_stride
int encrypt_chunk_stride(const char *filepath, long start_offset, int chunks, long chunk_size, long skip_distance) {
    // mode 0: Encrypt
    return process_chunk_stride(filepath, start_offset, chunks, chunk_size, skip_distance, 0);
}

// main.c에서 호출하는 이름: decrypt_chunk_stride
int decrypt_chunk_stride(const char *filepath, long start_offset, int chunks, long chunk_size, long skip_distance) {
    // mode 1: Decrypt
    return process_chunk_stride(filepath, start_offset, chunks, chunk_size, skip_distance, 1);
}