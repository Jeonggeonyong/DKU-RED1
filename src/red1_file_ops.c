#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <dirent.h>
#include <errno.h>

#include "red1_file_ops.h"

char file_queue[MAX_FILES][PATH_MAX];
int file_count = 0;

/**
 * @brief 내부 재귀 탐색 함수
 * 실제 디렉터리 순회를 담당하는 재귀함수
 * 이미 fork된 자식 프로세스 내부에서 동작하므로
 * 탐색 중 치명적인 오류(무한 루프, 허니팟 작동)가 발생해도 메인 프로세스에 영향 없음
 */
static void _scan_recursive_worker(const char *base_path, int pipe_fd) {
    DIR *dir = opendir(base_path);
    if (!dir) return;

    struct dirent *entry;
    char full_path[PATH_MAX];
    struct stat st;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (entry->d_name[0] == '.') continue; // 숨김 파일 무시

        snprintf(full_path, sizeof(full_path), "%s/%s", base_path, entry->d_name);

        // lstat 수행
        if (lstat(full_path, &st) == 0) {
            if (S_ISREG(st.st_mode)) {
                // 일반 파일 발견 시 파이프로 전송
                dprintf(pipe_fd, "%s\n", full_path);
            } 
            else if (S_ISDIR(st.st_mode)) {
                // 디렉터리 발견 시 재귀 호출
                _scan_recursive_worker(full_path, pipe_fd);
            }
        }
    }
    closedir(dir);
}

/**
 * @brief 메인 디렉터리 스캐너
 * 루트 경로의 각 항목에 대해 별도의 프로세스를 fork하여 탐색.
 */
void scan_directory_recursive(const char *base_path) {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe failed");
        return;
    }

    DIR *dir = opendir(base_path);
    if (!dir) {
        perror("opendir root failed");
        close(pipefd[0]);
        close(pipefd[1]);
        return;
    }

    struct dirent *entry;
    char full_path[PATH_MAX];

    // 루트 디렉터리의 항목 하나하나마다 정찰병(자식)을 보냄
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (entry->d_name[0] == '.') continue;

        snprintf(full_path, sizeof(full_path), "%s/%s", base_path, entry->d_name);

        pid_t pid = fork();
        
        if (pid == 0) { 
            // [Child Process: 정찰병]
            close(pipefd[0]); // 읽기 포트 닫기

            struct stat st;
            // 자식이 직접 만져봄 (lstat)
            if (lstat(full_path, &st) == 0) {
                if (S_ISREG(st.st_mode)) {
                    // 파일이면 바로 보고
                    dprintf(pipefd[1], "%s\n", full_path);
                }
                else if (S_ISDIR(st.st_mode)) {
                    // 하위 디렉터리 재귀함수 호출
                    // 만약 안쪽에 무한 함정이 있다면 해당 자식 프로세스만 영원히 돌거나 죽음.
                    _scan_recursive_worker(full_path, pipefd[1]);
                }
            }
            
            close(pipefd[1]);
            exit(0); // 임무 완료 후 소멸
        }
        // 부모는 자식의 생사를 확인하지 않고 바로 다음 항목으로 넘어감
    }
    closedir(dir);

    // 결과 수집 (살아 돌아온 정찰병들의 보고만 받음)
    close(pipefd[1]); 

    FILE *stream = fdopen(pipefd[0], "r");
    char line[PATH_MAX];
    
    while (fgets(line, sizeof(line), stream) != NULL) {
        line[strcspn(line, "\n")] = 0;
        if (file_count < MAX_FILES) {
            snprintf(file_queue[file_count], PATH_MAX, "%s", line);
            file_count++;
        }
    }
    fclose(stream);

    // 뒷정리
    while (wait(NULL) > 0);
}
