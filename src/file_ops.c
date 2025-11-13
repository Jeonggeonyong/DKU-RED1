#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "crypto.h"
#include "file_ops.h"


#define MAX_PATH 1024

/**
 * @brief 지정된 경로(base_path)로부터 모든 하위 파일과 디렉터리를 재귀적으로 순회
 * @param base_path 탐색을 시작할 디렉터리 경로
 */
void traverse_directory(const char *base_path, operation_mode mode, const char *extension) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char path_buffer[MAX_PATH];

    // 1. 디렉터리 열기
    if ((dir = opendir(base_path)) == NULL) {
        fprintf(stderr, "Error: Cannot open directory %s\n", base_path);
        return;
    }

    // 사용할 확장자 문자열 
    char ext_with_dot[10]; // (확장자 최대 8자리 + 점 + \0)
    snprintf(ext_with_dot, sizeof(ext_with_dot), ".%s", extension);
    size_t ext_len = strlen(ext_with_dot); // 7 (점 포함)

    // 2. 디렉터리 내의 모든 항목(entry) 읽기
    while ((entry = readdir(dir)) != NULL) {
        // 3. 무한 재귀 방지: '.' (현재) 및 '..' (상위) 디렉터리 무시
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        
        // 4. 전체 경로 생성 ("current_dir" + "/" + "filename")
        snprintf(path_buffer, sizeof(path_buffer), "%s/%s", base_path, entry->d_name);

        // 5. 파일/디렉터리의 상세 정보(stat) 가져오기
        if (stat(path_buffer, &statbuf) != 0) {
            fprintf(stderr, "Error: Cannot get stat for %s\n", path_buffer);
            continue;
        }

        // 6. 파일 타입 확인
        if (S_ISDIR(statbuf.st_mode)) {
            // 항목이 디렉터리일 경우
            printf("DIR : %s\n", path_buffer);
            traverse_directory(path_buffer, mode, extension);
        }
        else if (S_ISREG(statbuf.st_mode)) {
            // 항목이 일반 파일일 경우
            if (mode == MODE_ENCRYPT) { // [암호화 로직]
                
                // 하드코딩된 '.enc' 대신 'ext_with_dot' 사용
                if (strstr(path_buffer, ext_with_dot) != NULL) { // 이미 암호화 되었으면 pass
                    continue; 
                }

                // 확장자 변경
                char base_path_buffer[MAX_PATH]; 
                char *last_dot = strrchr(path_buffer, '.');
                if (last_dot != NULL && last_dot != path_buffer && strchr(last_dot, '/') == NULL) { 
                    size_t base_len = last_dot - path_buffer;
                    strncpy(base_path_buffer, path_buffer, base_len);
                    base_path_buffer[base_len] = '\0';
                }
                else {
                    strcpy(base_path_buffer, path_buffer);
                }

                // 암호화된 파일 경로 생성 (버퍼 크기 동적 계산)
                char encrypted_path[MAX_PATH + ext_len + 1]; 
                snprintf(encrypted_path, sizeof(encrypted_path), "%s.%s", base_path_buffer, extension);

                // crypto 모듈의 함수 호출
                if (encrypt_file_aes256(path_buffer, encrypted_path) == 0) {
                    printf("  -> Encrypted: %s\n", encrypted_path);
                    remove(path_buffer); 
                }
                else fprintf(stderr, "  -> Encryption FAILED for %s\n", path_buffer);
            
            }
            else if (mode == MODE_DECRYPT) { // [복호화 로직]
                // 하드코딩된 '.enc' 대신 'ext_with_dot' 사용
                if (strstr(path_buffer, ext_with_dot) != NULL) {
                    char decrypted_path[MAX_PATH];
                    // 하드코딩된 길이 대신 'ext_len' 사용
                    size_t original_len = strlen(path_buffer) - ext_len;
                    strncpy(decrypted_path, path_buffer, original_len);
                    decrypted_path[original_len] = '\0'; // Null-terminate

                    // crypto 모듈의 복호화 함수 호출
                    if (decrypt_file_aes256(path_buffer, decrypted_path) == 0) {
                        printf("  -> Decrypted: %s\n", decrypted_path);
                        remove(path_buffer);
                    } else fprintf(stderr, "  -> Decryption FAILED for %s\n", path_buffer); 
                }
            }
        }
        else printf("OTHER: %s\n", path_buffer); // (심볼릭 링크, 소켓 등 기타 파일 타입은 무시)
    }

    // 7. 디렉터리 닫기
    closedir(dir);
}