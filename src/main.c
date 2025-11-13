#include <stdio.h>
#include <string.h>
#include <stdlib.h> 
#include <time.h>
#include "file_ops.h" 


static void generate_random_string(char *buf, int len) {
    // 확장자에 사용하기 좋은 문자들 (o, 0, O, l, 1 등은 뺌)
    static const char charset[] = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    
    if (len <= 0) return;
    
    for (int i = 0; i < len; i++) {
        int key = rand() % (sizeof(charset) - 2); // -2 (null terminator + 1)
        buf[i] = charset[key];
    }
    buf[len] = '\0';
}

/**
 * @brief 프로그램 사용법을 출력하는 헬퍼 함수
 */
void print_usage(const char *prog_name) {
    fprintf(stderr, "Usage: %s [mode] <target_path>\n", prog_name);
    fprintf(stderr, "Modes:\n");
    fprintf(stderr, "  -e    Encrypt mode\n");
    fprintf(stderr, "  -d    Decrypt mode\n");
}

/**
 * @brief 프로그램 시작점 (Entry Point)
 */
int main(int argc, char *argv[]) {
    // 인자 개수 확인 
    if (argc != 3) {
        fprintf(stderr, "Error: Invalid arguments.\n\n");
        print_usage(argv[0]);
        return 1; // 오류 코드로 종료
    }

    // 기본 세팅
    srand(time(NULL));
    char random_extension[7]; // 6글자 + 1 (null terminator)
    generate_random_string(random_extension, 6);
    
    // 두 번째 인자로 모드 설정
    operation_mode mode;
    const char *start_path;
    if (strcmp(argv[1], "-e") == 0) mode = MODE_ENCRYPT;
    else if (strcmp(argv[1], "-d") == 0) mode = MODE_DECRYPT;
    else {
        fprintf(stderr, "Error: Invalid mode '%s'\n\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }

    // 세 번째 인자를 탐색 경로로 설정
    start_path = argv[2];
    printf("--- Start Traversal ---\n");
    printf("  Target Mode: %s\n", (mode == MODE_ENCRYPT) ? "ENCRYPT" : "DECRYPT");
    printf("  Target Path: %s\n", start_path);
    printf("  Using Extension: .%s\n", random_extension);
    printf("------------------------\n");
    
    // file_ops 모듈의 함수를 '모드'와 함께 호출
    traverse_directory(start_path, mode, random_extension);
    
    printf("------------------------\n");
    printf("--- End Traversal ---\n");

    return 0;
}