#include "neonext.h"
#include "ow-crypt.h"

#include <errno.h>
#include <string.h>
#include <fcntl.h>
#ifdef _WIN32
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
typedef SSIZE_T ssize_t;
#else
#include <unistd.h>
#endif

#define DEBUG_EXTENSION

#ifndef DEBUG_EXTENSION
#define DBGPRINT
#else
#define DBGPRINT(msg, ...) { fprintf(stderr, msg, __VA_ARGS__); }
#endif

#ifndef UNUSED
#define UNUSED(x) (void)(x)
#endif // !UNUSED
#define Ne_UNUSED_PARAMS(x)     UNUSED(x)

#ifdef __cplusplus
extern "C" {
#endif

const struct Ne_MethodTable *Ne;

#define BCRYPT_HASHSIZE                 (64)
#define RANDBYTES                       (16)
#define CRYPT_GENSALT_OUTPUT_SIZE       (7 + 22 + 1)
#define BCRYPT_ERR_SUCCESS               0
#define BCRYPT_ERR_NO_SECURE_DATA        1
#define BCRYPT_ERR_PARTIAL_DATA          2
#define BCRYPT_ERR_RANDOM_FAILED         3
#define BCRYPT_ERR_READ_FAILED           4
#define BCRYPT_ERR_SALT_FAILED           5
#define BCRYPT_ERR_INVALID_HASH          6
#define BCRYPT_ERR_INVALID_FACTOR        7

int Ne_INIT(const struct Ne_MethodTable *methodtable)
{
    Ne = methodtable;
    return Ne_SUCCESS;
}

Ne_CONST_INT(Ne_BCRYPT_HASHSIZE,            BCRYPT_HASHSIZE);
Ne_CONST_INT(Ne_CRYPT_GENSALT_OUTPUT_SIZE,  CRYPT_GENSALT_OUTPUT_SIZE);
Ne_CONST_INT(Ne_BCRYPT_ERR_SUCCESS,         BCRYPT_ERR_SUCCESS);
Ne_CONST_INT(Ne_BCRYPT_ERR_NO_SECURE_DATA,  BCRYPT_ERR_NO_SECURE_DATA);
Ne_CONST_INT(Ne_BCRYPT_ERR_PARTIAL_DATA,    BCRYPT_ERR_PARTIAL_DATA);
Ne_CONST_INT(Ne_BCRYPT_ERR_RANDOM_FAILED,   BCRYPT_ERR_RANDOM_FAILED);
Ne_CONST_INT(Ne_BCRYPT_ERR_READ_FAILED,     BCRYPT_ERR_READ_FAILED);
Ne_CONST_INT(Ne_BCRYPT_ERR_SALT_FAILED,     BCRYPT_ERR_SALT_FAILED);
Ne_CONST_INT(Ne_BCRYPT_ERR_INVALID_HASH,    BCRYPT_ERR_INVALID_HASH);
Ne_CONST_INT(Ne_BCRYPT_ERR_INVALID_FACTOR,  BCRYPT_ERR_INVALID_FACTOR);


#ifndef _WIN32
static int try_close(int fd)
{
    int ret;
    for (;;) {
        errno = 0;
        ret = close(fd);
        if (ret == -1 && errno == EINTR) {
            continue;
        }
        break;
    }
    return ret;
}

static int try_read(int fd, char *out, size_t count)
{
    size_t total;
    ssize_t partial;

    total = 0;
    while (total < count) {
        for (;;) {
            errno = 0;
            partial = read(fd, out + total, count - total);
            if (partial == -1 && errno == EINTR) {
                continue;
            }
            break;
        }
        if (partial < 1) {
            return -1;
        }
        total += partial;
    }
    return 0;
}
#endif
/*
 * This method is commonly used in crypto libraries like NaCl, but
 * there is nothing that prevents a compiler from optimizing this
 * function and making it vulnerable to a timing attack, or worse.
 * Return value is zero if both strings are equal and nonzero otherwise.
 */
static int timing_safe_strcmp(const char *str1, const char *str2)
{
    size_t len1 = strlen(str1);
    size_t len2 = strlen(str2);

    // Both strings should always have the same length!
    if (len1 != len2) {
        return 1;
    }

    int ret = 0;
    for (size_t i = 0; i < len1; ++i) {
        // Force unsigned for bitwise operations.
        ret |= ((const unsigned char)str1[i] ^ (const unsigned char)str2[i]);
    }
    return ret;
}

Ne_FUNC(Ne_generatesalt)
{
    int factor = Ne_PARAM_INT(0);

    char input[RANDBYTES];
    char salt[BCRYPT_HASHSIZE];
    char *aux = NULL;
#ifdef _WIN32
    HCRYPTPROV hCryptProv;
    if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, 0)) {
        // No default context/container was found, so we'll attempt to just create one.
        if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
            Ne_RETURN_INT(BCRYPT_ERR_NO_SECURE_DATA);
        }
    }
    if (!CryptGenRandom(hCryptProv, (DWORD)RANDBYTES, (BYTE*)input)) {
        Ne_RETURN_INT(BCRYPT_ERR_READ_FAILED);
    }
    if (!CryptReleaseContext(hCryptProv, 0)) {
        Ne_RETURN_INT(BCRYPT_ERR_RANDOM_FAILED);
    }
#else
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        Ne_RETURN_INT(BCRYPT_ERR_NO_SECURE_DATA);
    }
    if (try_read(fd, input, RANDBYTES) != 0) {
        if (try_close(fd) != 0) {
            Ne_RETURN_INT(BCRYPT_ERR_READ_FAILED);
        }
        Ne_RETURN_INT(BCRYPT_ERR_PARTIAL_DATA);
    }
    if (try_close(fd) != 0) {
        Ne_RETURN_INT(BCRYPT_ERR_RANDOM_FAILED);
    }
#endif
    if (factor < 4 || factor > 31) {
        Ne_RETURN_INT(BCRYPT_ERR_INVALID_FACTOR);
    }
    aux = crypt_gensalt_rn("$2a$", factor, input, RANDBYTES, salt, BCRYPT_HASHSIZE);
    Ne->cell_set_string(Ne_OUT_PARAM(0), salt);
    Ne_RETURN_INT((aux == NULL) ? BCRYPT_ERR_SALT_FAILED : BCRYPT_ERR_SUCCESS);
}

Ne_FUNC(Ne_hashpassword)
{
    const char *passwd = Ne_PARAM_STRING(0);
    const char *salt = Ne_PARAM_STRING(1);
    char hash[BCRYPT_HASHSIZE];

    char *aux = crypt_rn(passwd, salt, hash, BCRYPT_HASHSIZE);
    Ne->cell_set_string(Ne_OUT_PARAM(0), hash);
    Ne_RETURN_INT((aux == NULL) ? BCRYPT_ERR_NO_SECURE_DATA : BCRYPT_ERR_SUCCESS);
}

Ne_FUNC(Ne_checkpw)
{
    Ne_UNUSED_PARAMS(out_params);  // Avoid compiler warning
    const char *passwd = Ne_PARAM_STRING(0);
    const char *hash = Ne_PARAM_STRING(1);
    char outhash[BCRYPT_HASHSIZE];

    if (crypt_rn(passwd, hash, outhash, BCRYPT_HASHSIZE) == NULL) {
        Ne_RETURN_BOOL(0);
    }
    Ne_RETURN_BOOL(timing_safe_strcmp(hash, outhash) == 0);
}

#ifdef __cplusplus
}
#endif
