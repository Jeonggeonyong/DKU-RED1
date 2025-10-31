#include <stdio.h>
#include "file_ops.h" 

/**
 * @brief 프로그램 시작점 (Entry Point)
 */
int main() {
    // 탐색을 시작할 경로
    const char *start_path = "."; // '.'는 현재 디렉터리를 의미

    printf("--- Start Traversal from '%s' ---\n", start_path);
    
    // 2. file_ops 모듈의 함수를 호출합니다.
    traverse_directory(start_path);
    
    printf("--- End Traversal ---\n");

    return 0;
}