#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define BUFFER_SIZE 4096

// 실제 구현 시에는 하드코딩 X
// 256비트 (32바이트) 키
static const unsigned char aes_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};

// 128비트 (16바이트) 초기화 벡터 (IV)
static const unsigned char aes_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};


/**
 * @brief openssl error 처리
 */
void handle_openssl_errors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}


/**
 * @brief AES-256-CBC 알고리즘을 사용해 파일을 암호화
 */
int encrypt_file_aes256(const char *input_file, const char *output_file) {
    FILE *in_file, *out_file;
    EVP_CIPHER_CTX *ctx;
    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len;
    int ret = -1;

    // 파일 열기
    in_file = fopen(input_file, "rb");
    if (!in_file) {
        perror("fopen (input)");
        return -1;
    }
    out_file = fopen(output_file, "wb");
    if (!out_file) {
        perror("fopen (output)");
        fclose(in_file);
        return -1;
    }

    // openssl 암호화 컨텍스트 생성
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_openssl_errors();
        goto cleanup;
    }

    // 암호화 초기화
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv)) { 
        handle_openssl_errors();
        goto cleanup;
    }

    // 파일 읽기 -> 평문 암호화 -> 암호문 쓰기
    while ((in_len = fread(in_buf, 1, BUFFER_SIZE, in_file)) > 0) {
        if (1 != EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, in_len)) {
            handle_openssl_errors();
            goto cleanup;
        }
        fwrite(out_buf, 1, out_len, out_file);
    }
    
    // 암호화 마무리 (마지막 블록 처리)
    // BUFFER_SIZE로 나누어 떨어지지 않으면, 마지막 block이 ctx에 남음 -> Padding 처리 후 암호화 적용
    if (1 != EVP_EncryptFinal_ex(ctx, out_buf, &out_len)) { 
        handle_openssl_errors();
        goto cleanup;
    }
    fwrite(out_buf, 1, out_len, out_file);

    // 암호화 성공
    ret = 0;
    
cleanup : 
    EVP_CIPHER_CTX_free(ctx); // 컨텍스트 해제
    fclose(in_file);
    fclose(out_file);
    return ret;
}


/**
 * @brief AES-256-CBC 알고리즘을 사용해 파일을 복호화
 */
int decrypt_file_aes256(const char *input_file, const char *output_file) {
    FILE *in_file, *out_file;
    EVP_CIPHER_CTX *ctx;
    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len;
    int ret = -1;

    // 파일 열기
    in_file = fopen(input_file, "rb");
    if (!in_file) {
        perror("fopen (input)");
        return -1;
    }
    out_file = fopen(output_file, "wb");
    if (!out_file) {
        perror("fopen (output)");
        fclose(in_file);
        return -1;
    }

    // openssl 암호화 컨텍스트 생성
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_openssl_errors();
        goto cleanup;
    }

    // 암호화 초기화
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, aes_iv)) { 
        handle_openssl_errors();
        goto cleanup;
    }

    // 파일 읽기 -> 평문 암호화 -> 암호문 쓰기
    while ((in_len = fread(in_buf, 1, BUFFER_SIZE, in_file)) > 0) {
        if (1 != EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len)) {
            handle_openssl_errors();
            goto cleanup;
        }
        fwrite(out_buf, 1, out_len, out_file);
    }
    
    // 암호화 마무리 (마지막 블록 처리)
    // BUFFER_SIZE로 나누어 떨어지지 않으면, 마지막 block이 ctx에 남음 -> Padding 처리 후 암호화 적용
    if (1 != EVP_DecryptFinal_ex(ctx, out_buf, &out_len)) { 
        handle_openssl_errors();
        goto cleanup;
    }
    fwrite(out_buf, 1, out_len, out_file);

    // 암호화 성공
    ret = 0;
    
cleanup : 
    EVP_CIPHER_CTX_free(ctx); // 컨텍스트 해제
    fclose(in_file);
    fclose(out_file);
    return ret;
}
