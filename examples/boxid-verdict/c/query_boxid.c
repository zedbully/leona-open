#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define DEFAULT_ENDPOINT "https://leona.xiyanshan.com/v1/verdict"

static int endpoint_is_valid(const char *endpoint, int allow_loopback_http) {
    const char *https = "https://";
    const char *http = "http://";
    const char *authority = NULL;
    int scheme_allowed = 0;
    if (strncmp(endpoint, https, strlen(https)) == 0) {
        authority = endpoint + strlen(https);
        scheme_allowed = 1;
    } else if (strncmp(endpoint, http, strlen(http)) == 0 && allow_loopback_http) {
        authority = endpoint + strlen(http);
        scheme_allowed = (strncmp(authority, "127.0.0.1", 9) == 0
                && (authority[9] == ':' || authority[9] == '/'))
            || (strncmp(authority, "localhost", 9) == 0
                && (authority[9] == ':' || authority[9] == '/'))
            || (strncmp(authority, "[::1]", 5) == 0
                && (authority[5] == ':' || authority[5] == '/'));
    }
    if (!scheme_allowed || authority == NULL || authority[0] == '\0') return 0;
    const char *path = strchr(authority, '/');
    if (path == NULL || path == authority || strcmp(path, "/v1/verdict") != 0) return 0;
    for (const char *cursor = authority; cursor < path; ++cursor) {
        unsigned char ch = (unsigned char)*cursor;
        if (ch == '@' || ch == '?' || ch == '#' || ch == '\\' || ch <= 0x20 || ch == 0x7f) {
            return 0;
        }
    }
    return strchr(path, '?') == NULL && strchr(path, '#') == NULL;
}

struct response_buffer {
    char *data;
    size_t size;
};

static const char *require_env(const char *name) {
    const char *value = getenv(name);
    if (value == NULL || value[0] == '\0') {
        fprintf(stderr, "Missing required environment variable: %s\n", name);
        exit(2);
    }
    return value;
}

static long long now_millis(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return ((long long)tv.tv_sec * 1000LL) + (tv.tv_usec / 1000);
}

static void sha256_hex(const unsigned char *data, size_t len, char out[65]) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(out + (i * 2), "%02x", digest[i]);
    }
    out[64] = '\0';
}

static char *base64url_no_padding(const unsigned char *data, size_t len) {
    int encoded_len = 4 * ((int)(len + 2) / 3);
    unsigned char *tmp = malloc((size_t)encoded_len + 1);
    if (tmp == NULL) return NULL;
    EVP_EncodeBlock(tmp, data, (int)len);

    for (int i = 0; i < encoded_len; ++i) {
        if (tmp[i] == '+') tmp[i] = '-';
        if (tmp[i] == '/') tmp[i] = '_';
    }
    while (encoded_len > 0 && tmp[encoded_len - 1] == '=') {
        encoded_len--;
    }
    tmp[encoded_len] = '\0';
    return (char *)tmp;
}

static char *hmac_sha256_base64url(const char *secret, const char *text) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    HMAC(EVP_sha256(),
         secret,
         (int)strlen(secret),
         (const unsigned char *)text,
         strlen(text),
         digest,
         &digest_len);
    return base64url_no_padding(digest, digest_len);
}

static char *json_escape(const char *value) {
    size_t extra = 0;
    for (const char *p = value; *p; ++p) {
        if (*p == '"' || *p == '\\') extra++;
    }
    size_t len = strlen(value);
    char *out = malloc(len + extra + 1);
    if (out == NULL) return NULL;
    char *w = out;
    for (const char *p = value; *p; ++p) {
        if (*p == '"' || *p == '\\') *w++ = '\\';
        *w++ = *p;
    }
    *w = '\0';
    return out;
}

static char *header_pair(const char *name, const char *value) {
    size_t len = strlen(name) + 2 + strlen(value) + 1;
    char *out = malloc(len);
    if (out == NULL) return NULL;
    snprintf(out, len, "%s: %s", name, value);
    return out;
}

static char *random_nonce(void) {
    unsigned char raw[16];
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        exit(1);
    }
    return base64url_no_padding(raw, sizeof(raw));
}

static size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    struct response_buffer *buffer = userdata;
    char *next = realloc(buffer->data, buffer->size + total + 1);
    if (next == NULL) return 0;
    buffer->data = next;
    memcpy(buffer->data + buffer->size, ptr, total);
    buffer->size += total;
    buffer->data[buffer->size] = '\0';
    return total;
}

int main(void) {
    const char *secret = require_env("LEONA_SECRET_KEY");
    const char *box_id = require_env("BOX_ID");
    const char *endpoint = getenv("LEONA_ENDPOINT");
    if (endpoint == NULL || endpoint[0] == '\0') endpoint = DEFAULT_ENDPOINT;
    if (!endpoint_is_valid(endpoint, strcmp(getenv("LEONA_ALLOW_LOOPBACK_HTTP") == NULL
            ? "" : getenv("LEONA_ALLOW_LOOPBACK_HTTP"), "1") == 0)) {
        fprintf(stderr, "LEONA_ENDPOINT must be HTTPS /v1/verdict (or explicit loopback HTTP for local tests)\n");
        return 2;
    }

    char *escaped_box_id = json_escape(box_id);
    if (escaped_box_id == NULL) return 1;

    size_t body_len = strlen(escaped_box_id) + strlen("{\"boxId\":\"\"}") + 1;
    char *body = malloc(body_len);
    if (body == NULL) return 1;
    snprintf(body, body_len, "{\"boxId\":\"%s\"}", escaped_box_id);

    char timestamp[32];
    snprintf(timestamp, sizeof(timestamp), "%lld", now_millis());

    char body_sha256[65];
    sha256_hex((const unsigned char *)body, strlen(body), body_sha256);

    char *nonce = random_nonce();
    size_t signing_len = strlen(timestamp) + strlen(nonce) + strlen(body_sha256) + 3;
    char *signing_text = malloc(signing_len);
    if (signing_text == NULL) return 1;
    snprintf(signing_text, signing_len, "%s\n%s\n%s", timestamp, nonce, body_sha256);

    char *signature = hmac_sha256_base64url(secret, signing_text);
    if (signature == NULL) return 1;

    CURL *curl = curl_easy_init();
    if (curl == NULL) {
        fprintf(stderr, "curl_easy_init failed\n");
        return 1;
    }

    struct response_buffer response = {0};
    struct curl_slist *headers = NULL;
    size_t auth_value_len = strlen("Bearer ") + strlen(secret) + 1;
    char *auth_value = malloc(auth_value_len);
    if (auth_value == NULL) return 1;
    snprintf(auth_value, auth_value_len, "Bearer %s", secret);
    char *auth_header = header_pair("Authorization", auth_value);
    char *ts_header = header_pair("X-Leona-Timestamp", timestamp);
    char *nonce_header = header_pair("X-Leona-Nonce", nonce);
    char *sig_header = header_pair("X-Leona-Signature", signature);
    if (auth_header == NULL || ts_header == NULL || nonce_header == NULL || sig_header == NULL) {
        return 1;
    }
    headers = curl_slist_append(headers, auth_header);
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, ts_header);
    headers = curl_slist_append(headers, nonce_header);
    headers = curl_slist_append(headers, sig_header);

    curl_easy_setopt(curl, CURLOPT_URL, endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    if (rc != CURLE_OK) {
        fprintf(stderr, "Leona query failed: %s\n", curl_easy_strerror(rc));
    } else if (status < 200 || status >= 300) {
        fprintf(stderr, "Leona query failed: HTTP %ld\n%s\n", status,
                response.data == NULL ? "" : response.data);
    } else {
        printf("%s\n", response.data == NULL ? "" : response.data);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(sig_header);
    free(nonce_header);
    free(ts_header);
    free(auth_header);
    free(auth_value);
    free(response.data);
    free(signature);
    free(signing_text);
    free(nonce);
    free(body);
    free(escaped_box_id);
    return (rc == CURLE_OK && status >= 200 && status < 300) ? 0 : 1;
}
