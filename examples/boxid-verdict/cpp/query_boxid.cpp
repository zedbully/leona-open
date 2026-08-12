#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <chrono>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr const char *kDefaultEndpoint = "https://leona.xiyanshan.com/v1/verdict";

std::string require_env(const char *name) {
    const char *value = std::getenv(name);
    if (value == nullptr || value[0] == '\0') {
        throw std::runtime_error(std::string("Missing required environment variable: ") + name);
    }
    return value;
}

std::string env_or_default(const char *name, const char *fallback) {
    const char *value = std::getenv(name);
    return (value == nullptr || value[0] == '\0') ? fallback : value;
}

std::string validate_endpoint(const std::string &endpoint, bool allow_loopback_http) {
    const std::string https = "https://";
    const std::string http = "http://";
    size_t authority_start = std::string::npos;
    bool scheme_allowed = false;
    if (endpoint.rfind(https, 0) == 0) {
        authority_start = https.size();
        scheme_allowed = true;
    } else if (endpoint.rfind(http, 0) == 0 && allow_loopback_http) {
        authority_start = http.size();
        const std::string authority = endpoint.substr(authority_start);
        auto exact_host_prefix = [&authority](const std::string &host) {
            return authority.rfind(host, 0) == 0
                && authority.size() > host.size()
                && (authority[host.size()] == ':' || authority[host.size()] == '/');
        };
        scheme_allowed = exact_host_prefix("127.0.0.1")
            || exact_host_prefix("localhost")
            || exact_host_prefix("[::1]");
    }
    if (!scheme_allowed || authority_start == std::string::npos) {
        throw std::runtime_error("LEONA_ENDPOINT must use HTTPS (or explicit loopback HTTP for local tests)");
    }
    const size_t path = endpoint.find('/', authority_start);
    const std::string authority = path == std::string::npos
        ? std::string()
        : endpoint.substr(authority_start, path - authority_start);
    const bool invalid_authority = authority.find_first_of("@?#\\") != std::string::npos
        || authority.find_first_of(" \t\r\n") != std::string::npos;
    if (path == std::string::npos || path == authority_start || endpoint.substr(path) != "/v1/verdict"
        || invalid_authority) {
        throw std::runtime_error("LEONA_ENDPOINT must be an absolute /v1/verdict URL without credentials/query/fragment");
    }
    return endpoint;
}

std::string now_millis() {
    using namespace std::chrono;
    return std::to_string(duration_cast<milliseconds>(
        system_clock::now().time_since_epoch()).count());
}

std::string base64url_no_padding(const unsigned char *data, size_t len) {
    int encoded_len = 4 * static_cast<int>((len + 2) / 3);
    std::vector<unsigned char> tmp(static_cast<size_t>(encoded_len) + 1);
    EVP_EncodeBlock(tmp.data(), data, static_cast<int>(len));

    std::string out(reinterpret_cast<char *>(tmp.data()), static_cast<size_t>(encoded_len));
    for (char &ch : out) {
        if (ch == '+') ch = '-';
        if (ch == '/') ch = '_';
    }
    while (!out.empty() && out.back() == '=') {
        out.pop_back();
    }
    return out;
}

std::string random_nonce() {
    unsigned char raw[16];
    if (RAND_bytes(raw, sizeof(raw)) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return base64url_no_padding(raw, sizeof(raw));
}

std::string sha256_hex(const std::string &body) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(body.data()), body.size(), digest);
    std::ostringstream out;
    for (unsigned char byte : digest) {
        out << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return out.str();
}

std::string hmac_sha256_base64url(const std::string &secret, const std::string &text) {
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_len = 0;
    HMAC(EVP_sha256(),
         secret.data(),
         static_cast<int>(secret.size()),
         reinterpret_cast<const unsigned char *>(text.data()),
         text.size(),
         digest,
         &digest_len);
    return base64url_no_padding(digest, digest_len);
}

std::string json_escape(const std::string &value) {
    std::string out;
    out.reserve(value.size());
    for (char ch : value) {
        if (ch == '"' || ch == '\\') out.push_back('\\');
        out.push_back(ch);
    }
    return out;
}

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    auto *response = static_cast<std::string *>(userdata);
    response->append(ptr, size * nmemb);
    return size * nmemb;
}

}  // namespace

int main() {
    try {
        std::string secret = require_env("LEONA_SECRET_KEY");
        std::string box_id = require_env("BOX_ID");
        std::string endpoint = validate_endpoint(
            env_or_default("LEONA_ENDPOINT", kDefaultEndpoint),
            env_or_default("LEONA_ALLOW_LOOPBACK_HTTP", "0") == "1");

        std::string body = "{\"boxId\":\"" + json_escape(box_id) + "\"}";
        std::string timestamp = now_millis();
        std::string nonce = random_nonce();
        std::string signing_text = timestamp + "\n" + nonce + "\n" + sha256_hex(body);
        std::string signature = hmac_sha256_base64url(secret, signing_text);

        CURL *curl = curl_easy_init();
        if (curl == nullptr) {
            throw std::runtime_error("curl_easy_init failed");
        }

        std::string response;
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, ("Authorization: Bearer " + secret).c_str());
        headers = curl_slist_append(headers, "Content-Type: application/json");
        headers = curl_slist_append(headers, ("X-Leona-Timestamp: " + timestamp).c_str());
        headers = curl_slist_append(headers, ("X-Leona-Nonce: " + nonce).c_str());
        headers = curl_slist_append(headers, ("X-Leona-Signature: " + signature).c_str());

        curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

        CURLcode rc = curl_easy_perform(curl);
        long status = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (rc != CURLE_OK) {
            std::cerr << "Leona query failed: " << curl_easy_strerror(rc) << "\n";
            return 1;
        }
        if (status < 200 || status >= 300) {
            std::cerr << "Leona query failed: HTTP " << status << "\n" << response << "\n";
            return 1;
        }
        std::cout << response << "\n";
        return 0;
    } catch (const std::exception &e) {
        std::cerr << e.what() << "\n";
        return 1;
    }
}
