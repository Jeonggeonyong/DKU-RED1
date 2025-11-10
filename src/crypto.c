#include "crypto.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#define BUFFER_SIZE 4096

//전역 상수 선언. 최초 (N*100)%는 전체 암호화, 이후 (100-N*100)%는 B개의 블록으로 나눈다.
static const double SELECTIVE_N = 0.3;
static const int SELECTIVE_B = 3;

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

static int process_file_selective(const char *input_file, const char *output_file, int mode);

// OpenSSL error 출력
void handle_openssl_errors(void) {
    ERR_print_errors_fp(stderr);
    // abort()로 인해 프로세서가 즉시 죽는 문제 발생 가능하여 제거
}

/*
 * in_fp를 Base64 디코딩으로 한 바퀴 훑어서 디코딩된 총 크기만 계산한다.
 *
 * 왜 필요한가:
 *   - 암호화 시 파일을 선택적으로 암호화한 뒤 Base64 인코딩을 수행한다.
 *   - Base64 인코딩으로 인해 파일 크기가 약 1.33배 증가하므로,
 *     복호화 시에는 원본(디코딩된) 크기를 알아야 P% 및 B 조각 계산이 가능하다.
 */
static long compute_decoded_size_base64(FILE *in_fp) {
    long total = 0;
    BIO *in_bio = NULL, *b64 = NULL;
    unsigned char buf[BUFFER_SIZE];
    int r;

    // Base64 읽기 체인
    in_bio = BIO_new_fp(in_fp, BIO_NOCLOSE);
    if (!in_bio) goto end;
    b64 = BIO_new(BIO_f_base64());
    if (!b64) goto end;
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, in_bio);

    // 디코딩만 하면서 길이 합산
    while ((r = BIO_read(b64, buf, sizeof(buf))) > 0) {
        total += r;
    }
    if (r < 0) { // read 에러
        total = -1;
    }

end:
    if (b64) BIO_free_all(b64); // in_bio까지 같이 해제
    // 파일 포인터 초기화
    rewind(in_fp);
    return total;
}

// Base64 인코딩용 BIO 생성 (out_fp 래핑)
static BIO* make_b64_write_bio(FILE *out_fp) {
    BIO *file = BIO_new_fp(out_fp, BIO_NOCLOSE);
    if (!file) return NULL;
    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) { BIO_free(file); return NULL; }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    return BIO_push(b64, file);
}

// Base64 디코딩용 BIO 생성 (in_fp 래핑)
static BIO* make_b64_read_bio(FILE *in_fp) {
    BIO *file = BIO_new_fp(in_fp, BIO_NOCLOSE);
    if (!file) return NULL;
    BIO *b64 = BIO_new(BIO_f_base64());
    if (!b64) { BIO_free(file); return NULL; }
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    return BIO_push(b64, file);
}

// 공통 read/write 래퍼: Base64 사용 시 BIO 경유, 아니면 FILE 경유
static int read_stream(void *buf, int size, FILE *fp, BIO *b64_in, int is_use_b64) {
    if (is_use_b64) return BIO_read(b64_in, buf, size);
    size_t n = fread(buf, 1, size, fp);
    if (n == 0 && ferror(fp)) return -1;
    return (int)n;
}
static int write_stream(const void *buf, int size, FILE *fp, BIO *b64_out, int is_use_b64) {
    if (is_use_b64) return BIO_write(b64_out, buf, size);
    size_t n = fwrite(buf, 1, size, fp);
    if (n != (size_t)size && ferror(fp)) return -1;
    return (int)n;
}

/**
 * @brief AES-256-CTR을 사용한 선택적 파일 암/복호화
 * - Encrypt: 평문을 읽어서 (선택 영역만) Encrypt -> 결과 전체를 Base64 인코딩하여 out에 기록
 * - Decrypt: 입력(Base64)을 먼저 디코딩해서 바이트 스트림을 얻고 -> 선택 영역만 Decrypt -> 평문 파일 작성
 */
static int process_file_selective(const char *input_file, const char *output_file, int mode) {
    FILE *in_file = NULL, *out_file = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char in_buf[BUFFER_SIZE], out_buf[BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    int in_len, out_len;
    int ret = -1;

    // Base64 BIO (필요한 쪽만 사용)
    BIO *b64_in = NULL, *b64_out = NULL;
    int use_b64_read = 0, use_b64_write = 0;


    long total_size = 0, n_bytes, remaining_bytes, segment_size;

    // 파일 열기
    in_file = fopen(input_file, "rb");
    if (!in_file) {
        perror("fopen (input)");
        return -1;
    }
    out_file = fopen(output_file, "wb");
    if (!out_file) {
        perror("fopen (output)");
        goto cleanup;
    }

    // 총 길이 계산
    if (mode == 0) {
        // ENCRYPT: 입력은 평문 파일 -> fseek/ftell로 파일 크기 계산
        if (fseek(in_file, 0, SEEK_END) != 0) { 
            error("fseek");
            goto cleanup;
        }
        total_size = ftell(in_file);
        if (total_size < 0) {
            perror("ftell");
            goto cleanup;
        }
        rewind(in_file);

        // 출력은 Base64로 쓰기
        b64_out = make_b64_write_bio(out_file);
        if (!b64_out) {
            fprintf(stderr, "Base64 write BIO create failed\n");
            goto cleanup;
        }
        use_b64_write = 1;
    } else {
        // DECRYPT: 입력은 Base64 -> 먼저 디코딩 길이 계산
        total_size = compute_decoded_size_base64(in_file);
        if (total_size < 0) {
            fprintf(stderr, "Base64 size compute failed\n");
            goto cleanup;
        }

        // 실제 처리용 디코딩 BIO 생성
        b64_in = make_b64_read_bio(in_file);
        if (!b64_in) {
            fprintf(stderr, "Base64 read BIO create failed\n");
            goto cleanup;
        }
        use_b64_read = 1;
    }

    // 0바이트 처리
    if (total_size == 0) { ret = 0; goto cleanup; }

    // N, B로 정해준 선택 영역 파라미터 계산
    int num_segments_b = (SELECTIVE_B > 0) ? SELECTIVE_B : 1;
    double percentage_n = (SELECTIVE_N < 0.0) ? 0.0 : ((SELECTIVE_N > 1.0) ? 1.0 : SELECTIVE_N);
    n_bytes = (long)(total_size * percentage_n);
    remaining_bytes = total_size - n_bytes;
    segment_size = (num_segments_b > 0) ? (remaining_bytes / num_segments_b) : remaining_bytes;

    // OpenSSL 암호화 컨텍스트 생성
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        handle_openssl_errors();
        goto cleanup;
    }
    if (mode == 0) {
        if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, aes_key, aes_iv)) {
            handle_openssl_errors(); goto cleanup;
        }
    } else {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, aes_key, aes_iv)) {
            handle_openssl_errors(); goto cleanup;
        }
    }

    // 1단계: 앞 (N*100)% 처리 (Encrypt/Decrypt)
    long bytes_to_process = n_bytes;
    while (bytes_to_process > 0) {
        int want = (bytes_to_process > BUFFER_SIZE) ? BUFFER_SIZE : (int)bytes_to_process;
        in_len = read_stream(in_buf, want, in_file, b64_in, use_b64_read);
        if (in_len <= 0) { 
            fprintf(stderr, "Error: Read error in P%% block\n"); goto cleanup;
        }
        if (mode == 0) {
            if (1 != EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, in_len)) {
                handle_openssl_errors();
                goto cleanup;
            }
            if (out_len > 0) {
                if (write_stream(out_buf, out_len, out_file, b64_out, use_b64_write) != out_len) {
                    fprintf(stderr, "Write failed\n"); 
                    goto cleanup;
                }
            }
        }
        else {
            if (1 != EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len)) {
                handle_openssl_errors();
                goto cleanup;
            }
            if (out_len > 0) {
                if (write_stream(out_buf, out_len, out_file, b64_out, use_b64_write) != out_len) {
                    fprintf(stderr, "Write failed\n");
                    goto cleanup;
                }
            }
        }
        bytes_to_process -= in_len;
    }

    // 2단계: (100 - N*100)%를 나머지 B개 조각으로 나눔
    if (segment_size > 0 && remaining_bytes > 0) {
        for (int i = 0; i < num_segments_b; i++) {
            long current_segment_size = (i == num_segments_b - 1) ?
                (remaining_bytes - (segment_size * (num_segments_b - 1))) : segment_size;
            if (current_segment_size == 0) continue;

            long encrypt_bytes = current_segment_size / 2;
            long skip_bytes = current_segment_size - encrypt_bytes;

            // [2-1] 앞 절반: Encrypt/Decrypt
            bytes_to_process = encrypt_bytes;
            while (bytes_to_process > 0) {
                int want = (bytes_to_process > BUFFER_SIZE) ? BUFFER_SIZE : (int)bytes_to_process;
                in_len = read_stream(in_buf, want, in_file, b64_in, use_b64_read);
                if (in_len <= 0) {
                    fprintf(stderr, "Error: Read error in segment (encrypt part)\n");
                    goto cleanup;
                }
                if (mode == 0) {
                    if (1 != EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, in_len)) {
                        handle_openssl_errors();
                        goto cleanup;
                    }
                    if (out_len > 0) {
                        if (write_stream(out_buf, out_len, out_file, b64_out, use_b64_write) != out_len) {
                            fprintf(stderr, "Write failed\n");
                            goto cleanup;
                        }
                    }
                }
                else {
                    if (1 != EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len)) {
                        handle_openssl_errors();
                        goto cleanup;
                    }
                    if (out_len > 0) {
                        if (write_stream(out_buf, out_len, out_file, b64_out, use_b64_write) != out_len) {
                            fprintf(stderr, "Write failed\n");
                            goto cleanup;
                        }
                    }
                }
                bytes_to_process -= in_len;
            }

            // [2-2] 뒤 절반: 평문 복사(Encrypt 모드에선 그대로 Base64로 인코딩되어 나감)
            bytes_to_process = skip_bytes;
            while (bytes_to_process > 0) {
                int want = (bytes_to_process > BUFFER_SIZE) ? BUFFER_SIZE : (int)bytes_to_process;
                in_len = read_stream(in_buf, want, in_file, b64_in, use_b64_read);
                if (in_len <= 0) {
                    fprintf(stderr, "Error: Read error in segment (skip part)\n");
                    goto cleanup;
                }
                // 암/복호화 없이 그대로 씀
                if (write_stream(in_buf, in_len, out_file, b64_out, use_b64_write) != in_len) {
                    fprintf(stderr, "Write failed\n");
                    goto cleanup;
                }
                bytes_to_process -= in_len;
            }
        }
    } else if (remaining_bytes > 0) {
        // 남은 부분 전체 평문 복사
        bytes_to_process = remaining_bytes;
        while (bytes_to_process > 0) {
            int want = (bytes_to_process > BUFFER_SIZE) ? BUFFER_SIZE : (int)bytes_to_process;
            in_len = read_stream(in_buf, want, in_file, b64_in, use_b64_read);
            if (in_len <= 0) {
                fprintf(stderr, "Error: Read error in remaining block\n");
                goto cleanup;
            }
            if (write_stream(in_buf, in_len, out_file, b64_out, use_b64_write) != in_len) {
                fprintf(stderr, "Write failed\n");
                goto cleanup; 
            }
            bytes_to_process -= in_len;
        }
    }

    // Final (CTR에선 보통 out_len=0)
    if (mode == 0) {
        if (1 != EVP_EncryptFinal_ex(ctx, out_buf, &out_len)) {
            handle_openssl_errors();
            goto cleanup;
        }
    } else {
        if (1 != EVP_DecryptFinal_ex(ctx, out_buf, &out_len)) {
            handle_openssl_errors();
            goto cleanup;
        }
    }
    if (out_len > 0) {
        if (write_stream(out_buf, out_len, out_file, b64_out, use_b64_write) != out_len) {
            fprintf(stderr, "Write failed (final)\n");
            goto cleanup;
        }
    }

    // Base64 out flush
    if (use_b64_write) {
        if (BIO_flush(b64_out) != 1) {
            fprintf(stderr, "BIO_flush failed\n");
            goto cleanup;
        }
        fflush(out_file);
    }
    ret = 0;

cleanup:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (b64_in) BIO_free_all(b64_in);
    if (b64_out) BIO_free_all(b64_out);
    if (in_file) fclose(in_file);
    if (out_file) fclose(out_file);
    return ret;
}

/**
 * @brief AES-256-CTR 선택적 암호화: 결과는 Base64 텍스트(.enc)에 저장
 */
int encrypt_file_aes256(const char *input_file, const char *output_file) {
    return process_file_selective(input_file, output_file, 0);
}

/**
 * @brief AES-256-CTR 선택적 복호화: 입력 .enc(Base64) -> 디코딩 후 선택적 복호화 -> 평문 복원
 */
int decrypt_file_aes256(const char *input_file, const char *output_file) {
    return process_file_selective(input_file, output_file, 1);
}