#ifndef CRYPTO_H
#define CRYPTO_H

/**
 * @brief AES-256-CBC 알고리즘을 사용해 파일을 암호화
 * @param input_file 원본 파일 경로
 * @param output_file 암호화되어 저장될 파일 경로
 * @return 성공 시 0, 실패 시 -1 반환
 */

 int encrypt_file_aes256(const char *input_file, const char *output_file);

/**
 * @brief AES-256-CBC 알고리즘을 사용해 파일을 복호화
 * @param input_file 암호화된 파일 경로
 * @param output_file 복호화되어 저장될 파일 경로
 * @return 성공 시 0, 실패 시 -1 반환
 */
int decrypt_file_aes256(const char *input_file, const char *output_file);

#endif // CRYPTO_H