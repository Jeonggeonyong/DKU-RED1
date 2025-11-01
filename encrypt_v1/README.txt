# encrypt_v1 -Directory Encryption Tool (C, OpenSSL)

- 개요
⦁	encrypt_v1.c는 리눅스 환경에서 디렉토리 내의 모든 일반 파일을 암호화한다.
⦁	OpenSSL AES-256-GCM을 이용하여 빠르고 안전한 암호화 가능.
 
- 컴파일 방법
⦁	OpenSSL 개발 패키지 필요. (sudo apt-get install -y build-essential libssl-dev)
⦁	gcc -O2 -Wall -Wextra -std=c11 encrypt_v1.c -lcrypto -o encrypt_v1

-  실행 방법
⦁	기본 실행: ./encrypt_v1 <directory>
⦁	재귀적 암호화(하위 디렉토리까지 전부): ./encrypt_v1 -R <directory>
⦁	'Enter passphrase:' 라는 문구가 출력되면 암호로 쓸 문자열 입력

- 동작 설명
⦁	각 파일은 '<파일이름>.enc' 형태로 저장된다.
⦁	디렉토리별 '.salt' 파일을 생성해, 동일한 디렉토리 내 파일들이 같은 키를 공유한다.
⦁	만일 파일 확장자가 .enc라면 해당 파일은 암호화하지 않고 패스.

- 추가사항 및 보완점
⦁	간헐적 암호화: 파일 크기 봐가면서 암호화 각기 다르게(현재는 100MB 이상의 파일들은 패스.)
⦁	삭제 func
⦁	디렉토리/파일 권한 변경
⦁	복호화(선택?)
⦁	방어기법 우회
⦁	makefile
⦁	암호화 실패 상황 보완

