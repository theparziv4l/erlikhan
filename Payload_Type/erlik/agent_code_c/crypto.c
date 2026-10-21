#include "common.h"
#include "crypto.h"
#include <bcrypt.h>

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *b64_encode(const unsigned char *in, size_t len, size_t *out_len) {
    size_t out = 4 * ((len + 2) / 3);
    char *dst = (char *)malloc(out + 1);
    size_t i, j;
    if (!dst)
        return NULL;
    for (i = 0, j = 0; i < len;) {
        unsigned int a = i < len ? in[i++] : 0;
        unsigned int b = i < len ? in[i++] : 0;
        unsigned int c = i < len ? in[i++] : 0;
        unsigned int triple = (a << 16) | (b << 8) | c;
        dst[j++] = b64_table[(triple >> 18) & 0x3F];
        dst[j++] = b64_table[(triple >> 12) & 0x3F];
        dst[j++] = b64_table[(triple >> 6) & 0x3F];
        dst[j++] = b64_table[triple & 0x3F];
    }
    for (i = 0; i < (3 - len % 3) % 3; i++)
        dst[out - 1 - i] = '=';
    dst[out] = '\0';
    if (out_len)
        *out_len = out;
    return dst;
}

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

unsigned char *b64_decode(const char *in, size_t *out_len) {
    size_t len = strlen(in), i, j;
    unsigned char *dst;
    if (len % 4 != 0)
        return NULL;
    for (i = 0; i + 2 < len; i++) {
        if (in[i] == '=')
            return NULL;
    }
    dst = (unsigned char *)malloc(len / 4 * 3 + 1);
    if (!dst)
        return NULL;
    for (i = 0, j = 0; i < len;) {
        int a = b64_val(in[i++]);
        int b = b64_val(in[i++]);
        int c = (in[i] == '=') ? 0 : b64_val(in[i]);
        i++;
        int d = (in[i] == '=') ? 0 : b64_val(in[i]);
        i++;
        if (a < 0 || b < 0 || c < 0 || d < 0) {
            free(dst);
            return NULL;
        }
        dst[j++] = (unsigned char)((a << 2) | (b >> 4));
        dst[j++] = (unsigned char)((b << 4) | (c >> 2));
        dst[j++] = (unsigned char)((c << 6) | d);
    }
    /* Trim padding bytes: count trailing '=' (max 2 for valid input). */
    if (len >= 1 && in[len - 1] == '=')
        j--;
    if (len >= 2 && in[len - 2] == '=')
        j--;
    if (out_len)
        *out_len = j;
    return dst;
}

int hex_decode(const char *hex, bytebuf_t *out) {
    size_t len = strlen(hex), i;
    unsigned char *dst;
    if (len % 2 != 0)
        return -1;
    dst = (unsigned char *)malloc(len / 2 + 1);
    if (!dst)
        return -1;
    for (i = 0; i < len; i += 2) {
        unsigned int v;
        if (sscanf(hex + i, "%2x", &v) != 1) {
            free(dst);
            return -1;
        }
        dst[i / 2] = (unsigned char)v;
    }
    out->data = dst;
    out->len = len / 2;
    return 0;
}

static int aes_cbc(const unsigned char *key32, const unsigned char *iv,
                   const unsigned char *in, size_t in_len, int encrypt, bytebuf_t *out) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    NTSTATUS st;
    ULONG out_len = 0, junk = 0;
    unsigned char *dst;
    /* BCrypt chains the IV buffer in place; work on a copy so the
     * caller's IV (copied into the envelope after this returns) survives. */
    unsigned char ivbuf[16];
    int rc = -1;
    out->data = NULL;
    out->len = 0;
    memcpy(ivbuf, iv, sizeof(ivbuf));
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC,
                           (ULONG)sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    st = BCryptGenerateSymmetricKey(alg, &key, NULL, 0, (PUCHAR)key32, 32, 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    if (encrypt) {
        st = BCryptEncrypt(key, (PUCHAR)in, (ULONG)in_len, NULL, (PUCHAR)ivbuf, 16,
                           NULL, 0, &out_len, BCRYPT_BLOCK_PADDING);
    } else {
        if (in_len % 16 != 0)
            goto done;
        st = BCryptDecrypt(key, (PUCHAR)in, (ULONG)in_len, NULL, (PUCHAR)ivbuf, 16,
                           NULL, 0, &out_len, BCRYPT_BLOCK_PADDING);
    }
    if (!BCRYPT_SUCCESS(st))
        goto done;
    dst = (unsigned char *)malloc(out_len + 1);
    if (!dst)
        goto done;
    if (encrypt) {
        st = BCryptEncrypt(key, (PUCHAR)in, (ULONG)in_len, NULL, (PUCHAR)ivbuf, 16,
                           dst, out_len, &junk, BCRYPT_BLOCK_PADDING);
    } else {
        st = BCryptDecrypt(key, (PUCHAR)in, (ULONG)in_len, NULL, (PUCHAR)ivbuf, 16,
                           dst, out_len, &junk, BCRYPT_BLOCK_PADDING);
    }
    if (!BCRYPT_SUCCESS(st)) {
        free(dst);
        goto done;
    }
    out->data = dst;
    out->len = junk;
    rc = 0;
done:
    if (key)
        BCryptDestroyKey(key);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

/* Constant-time compare for MAC verification. */
static int ct_equal(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char diff = 0;
    size_t i;
    for (i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static int hmac_sha256(const unsigned char *key, const unsigned char *m1, size_t m1_len,
                       const unsigned char *m2, size_t m2_len, unsigned char mac[32]) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_HASH_HANDLE hash = NULL;
    NTSTATUS st;
    int rc = -1;
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!BCRYPT_SUCCESS(st))
        return -1;
    st = BCryptCreateHash(alg, &hash, NULL, 0, (PUCHAR)key, 32, 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    st = BCryptHashData(hash, (PUCHAR)m1, (ULONG)m1_len, 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    st = BCryptHashData(hash, (PUCHAR)m2, (ULONG)m2_len, 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    st = BCryptFinishHash(hash, mac, 32, 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    rc = 0;
done:
    if (hash)
        BCryptDestroyHash(hash);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}

int mythic_seal_raw(const char *uuid36, const unsigned char *json, size_t json_len,
                    const char *crypto, const unsigned char *psk, bytebuf_t *out) {
    out->data = NULL;
    out->len = 0;
    if (strcmp(crypto, "none") == 0) {
        unsigned char *raw = (unsigned char *)malloc(ERLIK_UUID_LEN + json_len + 1);
        if (!raw)
            return -1;
        memcpy(raw, uuid36, ERLIK_UUID_LEN);
        memcpy(raw + ERLIK_UUID_LEN, json, json_len);
        raw[ERLIK_UUID_LEN + json_len] = '\0';
        out->data = raw;
        out->len = ERLIK_UUID_LEN + json_len;
        return 0;
    }
    if (strcmp(crypto, "aes256_hmac") == 0) {
        unsigned char iv[16], mac[32];
        bytebuf_t ct = {0};
        unsigned char *raw;
        size_t raw_len;
        if (!psk)
            return -1;
        if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
            return -1;
        if (aes_cbc(psk, iv, json, json_len, 1, &ct) != 0)
            return -1;
        if (hmac_sha256(psk, iv, sizeof(iv), ct.data, ct.len, mac) != 0) {
            bytebuf_free(&ct);
            return -1;
        }
        raw_len = ERLIK_UUID_LEN + sizeof(iv) + ct.len + sizeof(mac);
        raw = (unsigned char *)malloc(raw_len + 1);
        if (!raw) {
            bytebuf_free(&ct);
            return -1;
        }
        memcpy(raw, uuid36, ERLIK_UUID_LEN);
        memcpy(raw + ERLIK_UUID_LEN, iv, sizeof(iv));
        memcpy(raw + ERLIK_UUID_LEN + sizeof(iv), ct.data, ct.len);
        memcpy(raw + ERLIK_UUID_LEN + sizeof(iv) + ct.len, mac, sizeof(mac));
        bytebuf_free(&ct);
        raw[raw_len] = '\0';
        out->data = raw;
        out->len = raw_len;
        return 0;
    }
    return -1;
}

int mythic_open_raw(const unsigned char *raw, size_t raw_len,
                    const char *crypto, const unsigned char *psk,
                    char uuid36_out[37], bytebuf_t *json_out) {
    const unsigned char *blob;
    size_t blob_len;
    json_out->data = NULL;
    json_out->len = 0;
    if (raw_len < ERLIK_UUID_LEN)
        return -1;
    memcpy(uuid36_out, raw, ERLIK_UUID_LEN);
    uuid36_out[ERLIK_UUID_LEN] = '\0';
    blob = raw + ERLIK_UUID_LEN;
    blob_len = raw_len - ERLIK_UUID_LEN;
    if (strcmp(crypto, "none") == 0) {
        json_out->data = (unsigned char *)malloc(blob_len + 1);
        if (!json_out->data)
            return -1;
        memcpy(json_out->data, blob, blob_len);
        json_out->data[blob_len] = '\0';
        json_out->len = blob_len;
        return 0;
    }
    if (strcmp(crypto, "aes256_hmac") == 0) {
        unsigned char mac[32];
        const unsigned char *iv, *ct;
        size_t ct_len;
        bytebuf_t pt = {0};
        if (!psk || blob_len < 16 + 32 + 16)
            return -1;
        iv = blob;
        ct = blob + 16;
        ct_len = blob_len - 16 - 32;
        if (hmac_sha256(psk, iv, 16, ct, ct_len, mac) != 0)
            return -1;
        if (!ct_equal(mac, blob + blob_len - 32, 32))
            return -1;
        if (aes_cbc(psk, iv, ct, ct_len, 0, &pt) != 0)
            return -1;
        /* NUL-terminate for the JSON parser (buffer has +1 spare). */
        pt.data = (unsigned char *)realloc(pt.data, pt.len + 1);
        if (!pt.data)
            return -1;
        pt.data[pt.len] = '\0';
        *json_out = pt;
        return 0;
    }
    return -1;
}

int mythic_seal(const char *uuid36, const unsigned char *json, size_t json_len,
                const char *crypto, const unsigned char *psk, char **out_b64) {
    bytebuf_t raw = {0};
    *out_b64 = NULL;
    if (mythic_seal_raw(uuid36, json, json_len, crypto, psk, &raw) != 0)
        return -1;
    *out_b64 = b64_encode(raw.data, raw.len, NULL);
    bytebuf_free(&raw);
    return *out_b64 ? 0 : -1;
}

int mythic_open(const char *b64, const char *crypto, const unsigned char *psk,
                char uuid36_out[37], bytebuf_t *json_out) {
    bytebuf_t raw = {0};
    int rc;
    json_out->data = NULL;
    json_out->len = 0;
    raw.data = b64_decode(b64, &raw.len);
    if (!raw.data)
        return -1;
    rc = mythic_open_raw(raw.data, raw.len, crypto, psk, uuid36_out, json_out);
    bytebuf_free(&raw);
    return rc;
}

int gcm_open(const unsigned char *key32, const unsigned char *nonce, size_t nonce_len,
             const unsigned char *ct, size_t ct_len, bytebuf_t *out) {
    BCRYPT_ALG_HANDLE alg = NULL;
    BCRYPT_KEY_HANDLE key = NULL;
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
    NTSTATUS st;
    ULONG out_len = 0;
    unsigned char *dst;
    int rc = -1;
    out->data = NULL;
    out->len = 0;
    if (ct_len < 16)
        return -1;
    BCRYPT_INIT_AUTH_MODE_INFO(info);
    info.pbNonce = (PUCHAR)nonce;
    info.cbNonce = (ULONG)nonce_len;
    info.pbTag = (PUCHAR)(ct + ct_len - 16);
    info.cbTag = 16;
    st = BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    st = BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                           (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    st = BCryptGenerateSymmetricKey(alg, &key, NULL, 0, (PUCHAR)key32, 32, 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    st = BCryptDecrypt(key, (PUCHAR)ct, (ULONG)(ct_len - 16), &info, NULL, 0,
                       NULL, 0, &out_len, 0);
    if (!BCRYPT_SUCCESS(st))
        goto done;
    dst = (unsigned char *)malloc(out_len + 1);
    if (!dst)
        goto done;
    st = BCryptDecrypt(key, (PUCHAR)ct, (ULONG)(ct_len - 16), &info, NULL, 0,
                       dst, out_len, &out_len, 0);
    if (!BCRYPT_SUCCESS(st)) {
        free(dst);
        goto done;
    }
    dst[out_len] = '\0';
    out->data = dst;
    out->len = out_len;
    rc = 0;
done:
    if (key)
        BCryptDestroyKey(key);
    if (alg)
        BCryptCloseAlgorithmProvider(alg, 0);
    return rc;
}
