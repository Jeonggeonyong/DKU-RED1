#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>


#define MAX_PATH 1024

/**
 * @brief 지정된 경로(base_path)로부터 모든 하위 파일과 디렉터리를 재귀적으로 순회
 * @param base_path 탐색을 시작할 디렉터리 경로
 */
void traverse_directory(const char *base_path) {
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
    while ((entry = readdir(dir)) != NULL) {
        // 3. 무한 재귀 방지: '.' (현재) 및 '..' (상위) 디렉터리 무시
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

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
            traverse_directory(path_buffer);

        } else if (S_ISREG(statbuf.st_mode)) {
            // 항목이 일반 파일일 경우
            printf("FILE: %s\n", path_buffer);
            
            /* 
                여기에 실제 랜섬웨어 로직 작성
                예: encrypt_file(path_buffer);

                파일의 확장자 등 블랙리스트도 활용 가능
            */
        
        } else {
            // (심볼릭 링크, 소켓 등 기타 파일 타입은 무시)
            printf("OTHER: %s\n", path_buffer);
        }
    }

    // 7. 디렉터리 닫기
    closedir(dir);
}