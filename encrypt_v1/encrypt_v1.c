// encdir.c - Simple directory file encrypter (AES-256-GCM, non-FUSE)
// Build: gcc -O2 -Wall -Wextra -std=c11 encdir.c -lcrypto -o encdir
// Notes:
//  - Encrypts regular files in a directory to <name>.enc (non-recursive by default)
//  - Uses PBKDF2-HMAC-SHA256(pass, dir/.salt, iter) -> 32B key
//  - On-disk format per file:
//      [ MAGIC(8)="ENCDIRG\0" ][ VER(1)=1 ][ RSV(3)=0 ]
//      [ NONCE(12) ][ PLAIN_LEN(8, LE) ][ CIPHERTEXT... ][ TAG(16) ]
//  - Streams: header -> ciphertext chunks -> tag
//  - Creates temp file then fsync+rename (atomic-ish)
//  - Skips files already ending with ".enc"
//  - This file includes only ENCRYPT; no decrypt per user request.

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <termios.h>
#include <sys/random.h>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// ---------- Config ----------
#define MAGIC "ENCDIRG\0"       // 8 bytes incl. trailing NUL
#define VERSION 1
#define NONCE_LEN 12
#define TAG_LEN   16
#define SALT_LEN  16
#define KEY_LEN   32
#define DEFAULT_MAX_MB 100      // default per-file limit
#define DEFAULT_ITER  200000
#define CHUNK (64 * 1024)

// ---------- Portable zero ----------
static void secure_bzero(void *p, size_t n) {
#if defined(__STDC_LIB_EXT1__)
    memset_s(p, n, 0, n);
#else
    volatile unsigned char *vp = (volatile unsigned char*)p;
    while (n--) *vp++ = 0;
#endif
}

// ---------- Logging ----------
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(EXIT_FAILURE);
}
static void warnx(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

// ---------- Passphrase (TTY, no-echo) ----------
static int read_passphrase(char *buf, size_t buflen, const char *prompt) {
    if (!isatty(STDIN_FILENO)) {
        // read from stdin (piped)
        ssize_t n = read(STDIN_FILENO, buf, buflen - 1);
        if (n <= 0) return -1;
        // strip trailing newline
        while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) n--;
        buf[n] = '\0';
        return 0;
    }
    struct termios old, noecho;
    if (tcgetattr(STDIN_FILENO, &old) != 0) return -1;
    noecho = old; noecho.c_lflag &= ~ECHO;
    fprintf(stderr, "%s", prompt); fflush(stderr);
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &noecho) != 0) return -1;
    if (!fgets(buf, (int)buflen, stdin)) { tcsetattr(STDIN_FILENO, TCSAFLUSH, &old); return -1; }
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
    fprintf(stderr, "\n");
    size_t n = strlen(buf);
    while (n > 0 && (buf[n-1] == '\n' || buf[n-1] == '\r')) buf[--n] = '\0';
    return 0;
}

// ---------- KDF & salt ----------
static int load_or_create_salt(const char *dir, uint8_t salt[SALT_LEN]) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/.salt", dir);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        ssize_t r = read(fd, salt, SALT_LEN);
        close(fd);
        return (r == SALT_LEN) ? 0 : -1;
    }
    // create
    if (getrandom(salt, SALT_LEN, 0) != SALT_LEN) {
        if (RAND_bytes(salt, SALT_LEN) != 1) return -1;
    }
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    ssize_t w = write(fd, salt, SALT_LEN);
    close(fd);
    return (w == SALT_LEN) ? 0 : -1;
}

static int derive_key(const char *pass, const uint8_t *salt, int iter, uint8_t key[KEY_LEN]) {
    // PBKDF2-HMAC-SHA256
    if (!PKCS5_PBKDF2_HMAC(pass, (int)strlen(pass), salt, SALT_LEN, iter, EVP_sha256(), KEY_LEN, key)) {
        return -1;
    }
    return 0;
}

// ---------- Path helpers ----------
static int ends_with(const char *s, const char *suf) {
    size_t n = strlen(s), m = strlen(suf);
    return (n >= m) && (memcmp(s + n - m, suf, m) == 0);
}
static int join_path(char out[PATH_MAX], const char *a, const char *b) {
    if (snprintf(out, PATH_MAX, "%s/%s", a, b) >= PATH_MAX) return -1;
    return 0;
}
static int add_ext(char out[PATH_MAX], const char *path, const char *ext) {
    if (snprintf(out, PATH_MAX, "%s%s", path, ext) >= PATH_MAX) return -1;
    return 0;
}
static int make_tmp(char out[PATH_MAX], const char *final_path) {
    // create <final>.tmpXXXXXX
    if (snprintf(out, PATH_MAX, "%s.tmpXXXXXX", final_path) >= PATH_MAX) return -1;
    return 0;
}
static int is_regular_file_path(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}
static int is_dir_path(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) return 0;
    return S_ISDIR(st.st_mode);
}

// ---------- File header ----------
#pragma pack(push,1)
typedef struct {
    char     magic[8];       // "ENCDIRG\0"
    uint8_t  ver;            // 1
    uint8_t  rsv[3];         // 0
    uint8_t  nonce[NONCE_LEN];
    uint64_t plain_len;      // little-endian
} enc_hdr_t;
#pragma pack(pop)

static void le64_write(uint8_t out[8], uint64_t v) {
    for (int i = 0; i < 8; ++i) out[i] = (uint8_t)((v >> (8*i)) & 0xFF);
}

// ---------- AES-256-GCM stream encrypt ----------
static int encrypt_stream_gcm(int infd, int outfd,
                              const uint8_t key[KEY_LEN],
                              const uint8_t nonce[NONCE_LEN],
                              uint64_t plain_len) {
    int ret = -1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto out;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) goto out;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto out;

    // (Optional) AAD could include header fields; skip for simplicity

    uint8_t inbuf[CHUNK], outbuf[CHUNK];
    ssize_t r;
    int outlen;

    uint64_t remaining = plain_len;
    while (remaining > 0) {
        size_t to_read = (remaining > CHUNK) ? CHUNK : (size_t)remaining;
        r = read(infd, inbuf, to_read);
        if (r < 0) { ret = -2; goto out; }
        if (r == 0) break; // EOF
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)r) != 1) { ret = -3; goto out; }
        if (write(outfd, outbuf, outlen) != outlen) { ret = -4; goto out; }
        remaining -= (uint64_t)r;
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) { ret = -5; goto out; }
    if (outlen > 0) {
        if (write(outfd, outbuf, outlen) != outlen) { ret = -6; goto out; }
    }

    uint8_t tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) { ret = -7; goto out; }
    if (write(outfd, tag, TAG_LEN) != TAG_LEN) { ret = -8; goto out; }

    ret = 0;
out:
    secure_bzero(inbuf, sizeof(inbuf));
    secure_bzero(outbuf, sizeof(outbuf));
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// ---------- Encrypt one file ----------
static int encrypt_file(const char *inpath, const char *outpath,
                        const uint8_t key[KEY_LEN], uint64_t max_bytes) {
    // Stat & size limit
    struct stat st;
    if (stat(inpath, &st) != 0) { warnx("  -> stat failed: %s", strerror(errno)); return -1; }
    if (!S_ISREG(st.st_mode)) { warnx("  -> skip (not regular)"); return 1; }
    uint64_t plain_len = (uint64_t)st.st_size;
    if (plain_len > max_bytes) { warnx("  -> skip (size > limit)"); return 1; }

    // Open in/out
    int infd = open(inpath, O_RDONLY);
    if (infd < 0) { warnx("  -> open input failed: %s", strerror(errno)); return -1; }

    char tmp_template[PATH_MAX];
    if (make_tmp(tmp_template, outpath) < 0) { close(infd); warnx("  -> path too long"); return -1; }
    int tmpfd = mkstemp(tmp_template);
    if (tmpfd < 0) { warnx("  -> mkstemp failed: %s", strerror(errno)); close(infd); return -1; }

    // Header
    enc_hdr_t hdr = {0};
    memcpy(hdr.magic, MAGIC, 8);
    hdr.ver = VERSION;
    if (getrandom(hdr.nonce, NONCE_LEN, 0) != NONCE_LEN) {
        if (RAND_bytes(hdr.nonce, NONCE_LEN) != 1) {
            warnx("  -> nonce gen failed");
            close(infd); close(tmpfd); unlink(tmp_template); return -1;
        }
    }
    le64_write((uint8_t*)&hdr.plain_len, plain_len);

    // Write header
    if (write(tmpfd, &hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) {
        warnx("  -> write header failed: %s", strerror(errno));
        close(infd); close(tmpfd); unlink(tmp_template); return -1;
    }

    // Encrypt stream
    int enc_ret = encrypt_stream_gcm(infd, tmpfd, key, hdr.nonce, plain_len);
    if (enc_ret != 0) {
        warnx("  -> encrypt failed (%d)", enc_ret);
        close(infd); close(tmpfd); unlink(tmp_template); return -1;
    }

    // fsync and rename
    if (fsync(tmpfd) != 0) {
        warnx("  -> fsync failed: %s", strerror(errno));
        close(infd); close(tmpfd); unlink(tmp_template); return -1;
    }
    close(infd); close(tmpfd);

    if (rename(tmp_template, outpath) != 0) {
        warnx("  -> rename failed: %s", strerror(errno));
        unlink(tmp_template);
        return -1;
    }
    return 0;
}

// ---------- Walk directory (optionally recursive) ----------
static int process_dir(const char *dir, const uint8_t key[KEY_LEN],
                       int recursive, uint64_t max_bytes) {
    DIR *dp = opendir(dir);
    if (!dp) die("opendir failed: %s", strerror(errno));

    int count_ok = 0, count_skip = 0, count_err = 0;

    struct dirent *de;
    while ((de = readdir(dp))) {
        const char *name = de->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) continue;
        if (name[0] == '.') { // skip hidden files/dirs (optional; comment out if not desired)
            // continue;
        }
        char path[PATH_MAX];
        if (join_path(path, dir, name) != 0) { warnx("Path too long, skip"); count_skip++; continue; }

        if (is_dir_path(path)) {
            if (recursive) {
                int r = process_dir(path, key, recursive, max_bytes);
                if (r < 0) count_err++; // propagate errors summary
            }
            continue;
        }
        if (!is_regular_file_path(path)) {
            count_skip++; continue;
        }
        if (ends_with(name, ".enc")) {
            // already encrypted -> skip
            count_skip++; continue;
        }

        char out[PATH_MAX];
        if (add_ext(out, path, ".enc") != 0) { warnx("Path too long, skip"); count_skip++; continue; }
        if (access(out, F_OK) == 0) {
            warnx("Encrypting: %s\n  -> exists, skip: %s", path, out);
            count_skip++; continue;
        }

        fprintf(stderr, "Encrypting: %s\n", path);
        int r = encrypt_file(path, out, key, max_bytes);
        if (r == 0) {
            fprintf(stderr, "  -> Created: %s (success)\n", out);
            count_ok++;
        } else if (r > 0) {
            // skipped
            count_skip++;
        } else {
            count_err++;
        }
    }
    closedir(dp);
    fprintf(stderr, "Done. success=%d, skipped=%d, errors=%d\n", count_ok, count_skip, count_err);
    return (count_err == 0) ? 0 : -1;
}

// ---------- CLI ----------
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [-R] [--max=MB] [--iter=N] <dir>\n"
        "  -R           : recursive\n"
        "  --max=MB     : per-file size limit (default %d MB)\n"
        "  --iter=N     : PBKDF2 iterations (default %d)\n",
        prog, DEFAULT_MAX_MB, DEFAULT_ITER);
}

int main(int argc, char **argv) {
    int recursive = 0;
    uint64_t max_bytes = (uint64_t)DEFAULT_MAX_MB * 1024ULL * 1024ULL;
    int iter = DEFAULT_ITER;
    const char *dir = NULL;

    // simple arg parse
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-R") == 0) recursive = 1;
        else if (strncmp(argv[i], "--max=", 6) == 0) {
            long mb = strtol(argv[i] + 6, NULL, 10);
            if (mb > 0) max_bytes = (uint64_t)mb * 1024ULL * 1024ULL;
        } else if (strncmp(argv[i], "--iter=", 7) == 0) {
            long v = strtol(argv[i] + 7, NULL, 10);
            if (v > 1000) iter = (int)v;
        } else if (argv[i][0] == '-') {
            usage(argv[0]); return 1;
        } else {
            dir = argv[i];
        }
    }
    if (!dir) { usage(argv[0]); return 1; }
    if (!is_dir_path(dir)) die("Not a directory: %s", dir);

    // load/create salt
    uint8_t salt[SALT_LEN];
    if (load_or_create_salt(dir, salt) != 0) die("Failed to load/create salt in %s/.salt", dir);

    // passphrase
    char pass[1024];
    if (read_passphrase(pass, sizeof(pass), "Enter passphrase: ") != 0) die("Failed to read passphrase");

    // derive key
    uint8_t key[KEY_LEN];
    if (derive_key(pass, salt, iter, key) != 0) { secure_bzero(pass, sizeof(pass)); die("KDF failed"); }

    secure_bzero(pass, sizeof(pass));

    // OpenSSL init (not strictly needed in 1.1.1+, but harmless)
    // OPENSSL_init_crypto(0, NULL);

    int rc = process_dir(dir, key, recursive, max_bytes);

    secure_bzero(key, sizeof(key));
    secure_bzero(salt, sizeof(salt));
    return (rc == 0) ? 0 : 2;
}