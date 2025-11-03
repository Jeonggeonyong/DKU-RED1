#ifndef FILE_OPS_H
#define FILE_OPS_H

// 암호화/복호화 모드 정의 
typedef enum {
    MODE_ENCRYPT,
    MODE_DECRYPT
} operation_mode;

/**
 * @brief 지정된 경로(base_path)로부터 모든 하위 파일과 디렉터리를 재귀적으로 순회합니다.
 * @param base_path 탐색을 시작할 디렉터리 경로
 * @param mode 실행할 모드 (암호화 또는 복호화)
 */
void traverse_directory(const char *base_path, operation_mode mode);

#endif // FILE_OPS_H