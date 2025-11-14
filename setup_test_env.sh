#!/bin/bash

# HOME 디렉터리 기준
HOME_DIR="${HOME}"
BACKEND_DIR="$HOME_DIR/workspace/target"
MOUNT_POINT_DIR="$HOME_DIR/workspace/illusion"

# 테스트 디렉터리 이름 정의
TEST_DIR="$BACKEND_DIR"

# 1. 매번 깨끗한 테스트를 위해 기존 디렉터리 삭제
echo "Cleaning up previous '$TEST_DIR'..."
rm -rf "$TEST_DIR"
echo "Cleaning up previous '$MOUNT_POINT_DIR'..."
rm -rf "$MOUNT_POINT_DIR"

# 2. 메인 디렉터리 생성
echo "Creating test directory '$TEST_DIR'..."
mkdir -p "$TEST_DIR"
echo "Creating test directory '$MOUNT_POINT_DIR'..."
mkdir -p "$MOUNT_POINT_DIR"

# 3. 하위 디렉터리 생성
echo "Creating subdirectories..."
mkdir -p "$TEST_DIR/documents/work/projects"
mkdir -p "$TEST_DIR/documents/personal"
mkdir -p "$TEST_DIR/downloads"
mkdir -p "$TEST_DIR/empty_folder" # <-- 비어있는 폴더도 테스트용으로 유지

# 4. 테스트용 파일 생성 (echo로 파일 내용 채우기)
echo "Creating test files with content..."

echo "This is a test file at the root. We need to check if this content encrypts." > "$TEST_DIR/file_at_root.txt"
echo "# Project README file" > "$TEST_DIR/README.md"

echo "// C source code file for testing" > "$TEST_DIR/documents/work/projects/project_alpha.c"
echo "#define PROJECT_BETA_H_" > "$TEST_DIR/documents/work/projects/project_beta.h"

echo "Confidential Work Report - PDF content simulation." > "$TEST_DIR/documents/work/report.pdf"

echo "My personal notes. Is good!" > "$TEST_DIR/documents/personal/notes.txt"
# 'echo -e'는 \n (줄바꿈) 문자를 인식함
echo -e "TODO List:\n1. Finish ransomware project\n2. Get A+" > "$TEST_DIR/documents/personal/todo.list"

echo "This is a fake image file content." > "$TEST_DIR/downloads/image.jpg"
echo "I am a secret hidden file." > "$TEST_DIR/downloads/.hidden_file"


echo "Test environment created successfully inside '$TEST_DIR'!"
echo "Use 'cat $TEST_DIR/file_at_root.txt' to check content."