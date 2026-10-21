/* Golden-vector check: opens Mythic docs envelopes. Test-only; never linked
 * into the agent (agent builds use an explicit file list).
 *
 * Build: zig cc -target x86_64-windows-gnu vectors_test.c crypto.c cJSON.c
 *   -DTEST_BLOB1=".." -DTEST_BLOB2=".." -DTEST_BLOB3=".." -DTEST_PSK=".."
 *   -lbcrypt -o vectors.exe && wine vectors.exe (exit 0 = pass)
 */
#include "common.h"
#include "crypto.h"
#include "cJSON.h"

#ifndef TEST_BLOB1
#define TEST_BLOB1 ""
#endif
#ifndef TEST_BLOB2
#define TEST_BLOB2 ""
#endif
#ifndef TEST_BLOB3
#define TEST_BLOB3 ""
#endif
#ifndef TEST_PSK
#define TEST_PSK ""
#endif

static const char *jstr(cJSON *o, const char *k) {
    cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!v || !cJSON_IsString(v) || !v->valuestring)
        return "";
    return v->valuestring;
}

static int check(const char *blob, const unsigned char *psk, const char *want_uuid,
                 const char *want_action, const char *want_field, const char *want_value) {
    char uuid[37];
    bytebuf_t out = {0};
    cJSON *root = NULL;
    int rc = 1;
    if (mythic_open(blob, "aes256_hmac", psk, uuid, &out) != 0) {
        printf("FAIL: open\n");
        return 1;
    }
    if (strcmp(uuid, want_uuid) != 0) {
        printf("FAIL: uuid %s\n", uuid);
        goto done;
    }
    root = cJSON_ParseWithLength((const char *)out.data, (int)out.len);
    if (!root) {
        printf("FAIL: json\n");
        goto done;
    }
    if (strcmp(jstr(root, "action"), want_action) != 0) {
        printf("FAIL: action %s\n", jstr(root, "action"));
        goto done;
    }
    if (want_field && strcmp(jstr(root, want_field), want_value) != 0) {
        printf("FAIL: %s=%s\n", want_field, jstr(root, want_field));
        goto done;
    }
    rc = 0;
done:
    if (root)
        cJSON_Delete(root);
    bytebuf_free(&out);
    return rc;
}

int main(void) {
    bytebuf_t psk = {0};
    int rc = 0;
    psk.data = b64_decode(TEST_PSK, &psk.len);
    if (!psk.data || psk.len != 32) {
        printf("FAIL: psk\n");
        return 1;
    }
    rc |= check(TEST_BLOB1, psk.data, "80844d19-9bfc-47f9-b9af-c6b9144c0fdc",
                "checkin", "uuid", "80844d19-9bfc-47f9-b9af-c6b9144c0fdc");
    rc |= check(TEST_BLOB2, psk.data, "80844d19-9bfc-47f9-b9af-c6b9144c0fdc",
                "checkin", "id", "822bff1b-bda0-4bce-a4d3-a6bdb11b8a5f");
    rc |= check(TEST_BLOB3, psk.data, "822bff1b-bda0-4bce-a4d3-a6bdb11b8a5f",
                "get_tasking", NULL, NULL);
    bytebuf_free(&psk);
    if (rc == 0)
        printf("VECTORS-PASS\n");
    return rc;
}
