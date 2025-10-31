#!/bin/bash

# 테스트 디렉터리 이름 정의
TEST_DIR="test_environment"

# 1. 매번 깨끗한 테스트를 위해 기존 디렉터리 삭제
echo "Cleaning up previous '$TEST_DIR'..."
rm -rf "$TEST_DIR"

# 2. 메인 디렉터리 생성
echo "Creating test directory '$TEST_DIR'..."
mkdir -p "$TEST_DIR"

# 3. 하위 디렉터리 생성
echo "Creating subdirectories..."
mkdir -p "$TEST_DIR/documents/work/projects"
mkdir -p "$TEST_DIR/documents/personal"
mkdir -p "$TEST_DIR/downloads"
mkdir -p "$TEST_DIR/empty_folder"

# 4. 테스트용 빈 파일 생성
echo "Creating test files..."
touch "$TEST_DIR/file_at_root.txt"
touch "$TEST_DIR/README.md"
touch "$TEST_DIR/documents/work/projects/project_alpha.c"
touch "$TEST_DIR/documents/work/projects/project_beta.h"
touch "$TEST_DIR/documents/work/report.pdf"
touch "$TEST_DIR/documents/personal/notes.txt"
touch "$TEST_DIR/documents/personal/todo.list"
touch "$TEST_DIR/downloads/image.jpg"
touch "$TEST_DIR/downloads/.hidden_file"

echo "Test environment created successfully inside '$TEST_DIR'!"
echo "Use 'ls -R $TEST_DIR' to check the structure."

