//
//  Bismillah ar-Rahmaan ar-Raheem
//
//  CLI Tool for Mine
//
//  Mine is single header minimal cryptography library
//
//  Copyright (c) 2017 Muflihun Labs
//
//  This library is released under the Apache 2.0 license
//  https://github.com/muflihun/mine/blob/master/LICENSE
//
//  https://github.com/muflihun/mine
//  https://muflihun.github.io/mine
//  https://muflihun.com
//

#include <iomanip>
#include <cstring>
#include <sstream>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include "package/mine.h"

using namespace mine;

void displayUsage()
{
    // we want to keep the order so can't use std::map or std::unordered_map
    std::vector<std::pair<std::string, std::string>> options = {
        {"--version", "Display version information"},
        {"-e", "Encrypt / encode / inflate the data"},
        {"-d", "Decrypt / decrypt / deflate the data"},
        {"-g", "Generate a random key"},
        {"--aes", "AES operations"},
        {"--key", "Symmetric key for encryption / decryption"},
        {"--iv", "Initializaion vector for decription"},
        {"--base64", "Base64 operations"},
        {"--hex", "Base16 operations"},
        {"--length", "Specify key length"},
    };

    std::cout << "mine [-d | -e | -g | -s | -v] [--in <input_file_path>] [--key <key>] [--in-key <file_path>] [--out-public <output_file_path>] [--out-private <output_file_path>] [--iv <init vector>] [--base64] [--length <key_length>] [--aes [<key_length>]] [--hex]" << std::endl;
    std::cout << std::endl;
    const std::size_t LONGEST = 20;
    for (auto& option : options) {
        std::cout << "     " << option.first;
        for (std::size_t i = 0; i < LONGEST - option.first.length(); ++i) {
            std::cout << " ";
        }
        std::cout << option.second << std::endl;
    }
    std::cout << std::endl;
}

void displayVersion()
{
    std::cout << "Mine - Minimal cryptography library" << std::endl << "Version: " << MINE_VERSION << std::endl << "https://muflihun.com" << std::endl;
}

#define TRY try {
#define CATCH }  catch (const std::exception& e) { std::cout << "ERROR: " << e.what() << std::endl; }

void encryptAES(std::string& data, const std::string& key, std::string& iv)
{
    TRY
        bool newIv = iv.empty();
        std::cout << AES::cipher(data, key, iv);

        if (newIv) {
            std::cout << std::endl << "IV: " << iv << std::endl;
        }
    CATCH
}

void decryptAES(std::string& data, const std::string& key, std::string& iv)
{
    TRY
        std::cout << AES::decipher(data, key, iv);
    CATCH
}

void generateAESKey(int length)
{
    TRY
        std::cout << AES::generateRandomKey(length);
    CATCH
}

void encodeBase64(std::string& data)
{
    TRY
        std::cout << Base64::encode(data);
    CATCH
}

void decodeBase64(std::string& data)
{
    TRY
        std::cout << Base64::decode(data);
    CATCH
}

void encodeHex(std::string& data)
{
    TRY
        std::cout << Base16::encode(data);
    CATCH
}

void decodeHex(std::string& data)
{
    TRY
        std::cout << Base16::decode(data);
    CATCH
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        displayUsage();
        return 1;
    }

    if (strcmp(argv[1], "--version") == 0) {
        displayVersion();
        return 0;
    }

    // This is quick check for args, use getopt in future
    int type = -1; // Decryption encryption, generate, verify or sign

    std::string key;
    std::string iv;
    int keyLength = 256;
    std::string data;
    bool isAES = false;
    bool isBase64 = false;
    bool isHex = false;
    bool fileArgSpecified = false;

    for (int i = 0; i < argc; i++) {
        std::string arg(argv[i]);
        bool hasNext = i + 1 < argc;
        if (arg == "-d" && type == -1) {
            type = 1;
        } else if (arg == "-e" && type == -1) {
            type = 2;
        } else if (arg == "-g" && type == -1) {
            type = 3;
        } else if (arg == "--base64") {
            isBase64 = true;
        } else if (arg == "--hex") {
            isHex = true;
        } else if (arg == "--key" && hasNext) {
            key = argv[++i];
        } else if (arg == "--aes") {
            isAES = true;
            if (i + 1 < argc) {
                int k = atoi(argv[++i]);
                if (k > 0) {
                    keyLength = k;
                } else {
                    --i;
                }
            }
        } else if (arg == "--length" && hasNext) {
            keyLength = atoi(argv[++i]);
        } else if (arg == "--iv" && hasNext) {
            iv = argv[++i];
        } else if (arg == "--in" && hasNext) {
            fileArgSpecified = true;
            std::fstream fs;
            // Do not increment i here as we are only changing 'data'
            fs.open (argv[i + 1], std::fstream::binary | std::fstream::in);
            data = std::string((std::istreambuf_iterator<char>(fs) ),
                            (std::istreambuf_iterator<char>()));
            fs.close();
        }
    }

    if ((type == 1 || type == 2) && !fileArgSpecified) {
        std::stringstream ss;
        for (std::string line; std::getline(std::cin, line);) {
            ss << line << std::endl;
        }
        data = ss.str();
        // Remove last 'new line'
        data.erase(data.size() - 1);
    }

    if (type == 1) { // Decrypt / Decode
        if (isBase64 && key.empty() && iv.empty()) {
            // base64 decode
            decodeBase64(data);
        } else if (isHex && key.empty() && iv.empty()) {
            // hex to ascii
            decodeHex(data);
        } else {
            // AES decrypt (base64-flexible)
            decryptAES(data, key, iv);
        }
    } else if (type == 2) { // Encrypt / Encode
        if (isBase64 && key.empty() && iv.empty()) {
            encodeBase64(data);
        } else if (isHex && key.empty() && iv.empty()) {
            encodeHex(data);
        } else {
            encryptAES(data, key, iv);
        }
    } else if (type == 3) { // Generate
        if (isAES) {
            generateAESKey(keyLength);
        } else {
            std::cout << "ERROR: Please provide method (you probably forgot '--rsa' or '--aes')" << std::endl;
        }
    } else {
        displayUsage();
        return 1;
    }

    return 0;
}
