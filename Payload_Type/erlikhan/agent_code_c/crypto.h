#ifndef ERLIKHAN_CRYPTO_H
#define ERLIKHAN_CRYPTO_H

#include "common.h"

/* Base64 (standard alphabet). Callers free results. */
char *b64_encode(const unsigned char *in, size_t len, size_t *out_len);
unsigned char *b64_decode(const char *in, size_t *out_len);
int hex_decode(const char *hex, bytebuf_t *out);

/*
 * Mythic agent envelope, both directions:
 *   none:        base64(UUID + JSON)
 *   aes256_hmac: base64(UUID + IV(16) + AES256-CBC(JSON) + HMAC-SHA256(key, IV||ct))
 */
int mythic_seal(const char *uuid36, const unsigned char *json, size_t json_len,
                const char *crypto, const unsigned char *psk, char **out_b64);
int mythic_open(const char *b64, const char *crypto, const unsigned char *psk,
                char uuid36_out[37], bytebuf_t *json_out);

/* Raw variants carry the same bytes without base64 (dns frames raw). */
int mythic_seal_raw(const char *uuid36, const unsigned char *json, size_t json_len,
                    const char *crypto, const unsigned char *psk, bytebuf_t *out);
int mythic_open_raw(const unsigned char *raw, size_t raw_len,
                    const char *crypto, const unsigned char *psk,
                    char uuid36_out[37], bytebuf_t *json_out);

/* AES-GCM open for the config blob (12-byte nonce, 16-byte tag appended). */
int gcm_open(const unsigned char *key32, const unsigned char *nonce, size_t nonce_len,
             const unsigned char *ct, size_t ct_len, bytebuf_t *out);

#endif
