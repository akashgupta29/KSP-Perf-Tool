#pragma once

#include <Windows.h>
#include <ncrypt.h>
#include <iostream>
#include <chrono>
#include <cstring>
#include <mutex>
#include <vector>
#include <numeric>
#include "Utils.h"
using namespace std;
#pragma comment(lib, "ncrypt.lib")

class AesGcm256NoKg
{
public:
    NCRYPT_PROV_HANDLE  g_hProvider = 0;
    NCRYPT_KEY_HANDLE g_hKey = 0;
    DWORD keyLength = 256;

    void runTests(int threadCount, int testDuration)
    {
        SECURITY_STATUS status;

        // Initial setup - open a handle to the KSP and create a persisted key for encrypt/decrypt operations
        // MS_PLATFORM_CRYPTO_PROVIDER => TPM, MS_KEY_STORAGE_PROVIDER => KG
        status = NCryptOpenStorageProvider(&g_hProvider, MS_KEY_STORAGE_PROVIDER, 0);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptOpenStorageProvider failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            return;
        }

        // Generate the key
        status = NCryptCreatePersistedKey(g_hProvider, &g_hKey, NCRYPT_AES_ALGORITHM, NULL, 0, 0);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptCreatePersistedKey failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            NCryptFreeObject(g_hKey);
            return;
        }

        // Set the key length
        status = NCryptSetProperty(g_hKey, NCRYPT_LENGTH_PROPERTY, (PBYTE)&keyLength, sizeof(DWORD), 0);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptSetProperty failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            NCryptFreeObject(g_hKey);
            return;
        }

        // finalize the key
        status = NCryptFinalizeKey(g_hKey, 0);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptFinalizeKey failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            NCryptFreeObject(g_hKey);
            return;
        }

        status = NCryptSetProperty(g_hKey, NCRYPT_CHAINING_MODE_PROPERTY, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptSetProperty failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            NCryptFreeObject(g_hKey);
            return;
        }

        wprintf(L"\nCreated a persisted AES GCM 256 key!\n");

        // run sub-scenarios
        std::cout << "\n**** Executing Encrypt/Decrypt using AES GCM 256 ****" << std::endl;
        TestEncryptAesCbc256(threadCount, testDuration);
        TestDecryptAesCbc256(threadCount, testDuration);
        std::cout << "*******************************************************\n" << std::endl;

        // cleanup - delete the key, free up the ksp and key handle
        status = NCryptDeleteKey(g_hKey, 0);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptDeleteKey failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            NCryptFreeObject(g_hKey);
            return;
        }
        NCryptFreeObject(g_hProvider);
        NCryptFreeObject(g_hKey);
    }

private:
    void TestEncryptAesCbc256(int threadCount, int testDuration)
    {
        atomic_llong encrypt_count = 0;
        atomic_llong encrypt_duration_running_sum = 0;

        vector<thread> threads(threadCount);
        for (int idx = 0; idx < threadCount; ++idx)
        {
            threads[idx] = thread([&]() {
                SECURITY_STATUS status;
                BYTE plainText[128];
                generateRandomByteArray(128, plainText);
                DWORD plainTextSize = sizeof(plainText);
                DWORD cipherTextSize = 0;
                PBYTE cipherText = NULL;

                std::chrono::time_point<std::chrono::high_resolution_clock> start_time, end_time;
                std::int64_t execution_time;

                auto loop_start_time = std::chrono::steady_clock::now();
                while (std::chrono::steady_clock::now() - loop_start_time < std::chrono::seconds(testDuration))
                {
                    start_time = std::chrono::high_resolution_clock::now();

                    constexpr ULONG AES_256_TAG_BYTE_LENGTH = 16;
                    constexpr ULONG AES_256_INIT_VECTOR_BYTE_LENGTH = 12;
                    constexpr ULONG AES_256_INIT_VECTOR_ULONG_LENGTH = AES_256_INIT_VECTOR_BYTE_LENGTH / sizeof(ULONG);

                    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthCipherModeInfo = { 0 };
                    BYTE Tag[AES_256_TAG_BYTE_LENGTH];
                    BYTE InitVector[AES_256_INIT_VECTOR_BYTE_LENGTH];
                    BCRYPT_INIT_AUTH_MODE_INFO(AuthCipherModeInfo);

                    AuthCipherModeInfo.pbNonce = InitVector;
                    AuthCipherModeInfo.cbNonce = sizeof(InitVector);
                    AuthCipherModeInfo.pbTag = Tag;
                    AuthCipherModeInfo.cbTag = sizeof(Tag);

                    NCRYPT_CIPHER_PADDING_INFO  paddingInfo;
                    paddingInfo.dwFlags = NCRYPT_CIPHER_OTHER_PADDING_FLAG;
                    paddingInfo.cbIV = 0;
                    paddingInfo.pbIV = NULL;
                    paddingInfo.cbOtherInfo = sizeof(AuthCipherModeInfo);
                    paddingInfo.pbOtherInfo = (PUCHAR)&AuthCipherModeInfo;
                    paddingInfo.cbSize = sizeof(NCRYPT_CIPHER_PADDING_INFO);

                    // Determine the size of the encrypted data
                    status = NCryptEncrypt(g_hKey, plainText, plainTextSize, &paddingInfo, NULL, 0, &cipherTextSize, NCRYPT_PAD_CIPHER_FLAG);
                    if (status != ERROR_SUCCESS)
                    {
                        wprintf(L"NCryptEncrypt1 failed with %x\n", status);
                        NCryptFreeObject(g_hProvider);
                        NCryptFreeObject(g_hKey);
                        return;
                    }

                    // Allocate a buffer for the encrypted data
                    cipherText = new BYTE[cipherTextSize];

                    // Encrypt the data
                    status = NCryptEncrypt(g_hKey, plainText, plainTextSize, &paddingInfo, cipherText, cipherTextSize, &cipherTextSize, NCRYPT_PAD_CIPHER_FLAG);

                    if (status != ERROR_SUCCESS)
                    {
                        wprintf(L"NCryptEncrypt2 failed with %x\n", status);
                        NCryptFreeObject(g_hProvider);
                        NCryptFreeObject(g_hKey);
                        return;
                    }

                    delete[] cipherText;
                    end_time = std::chrono::high_resolution_clock::now();
                    execution_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
                    encrypt_count++;
                    encrypt_duration_running_sum += execution_time;
                }
            });
        }

        for (int idx = 0; idx < threadCount; ++idx)
        {
            threads[idx].join();
        }

        // Generate average time report for Encrypt operation
        double avg_execution_time = calculateAverage1(encrypt_duration_running_sum, encrypt_count);
        double rps = calculateRps(testDuration, encrypt_count);
        std::cout << "[Encrypt] [AES 256 - CBC] Average execution time: " << avg_execution_time << " microseconds; RPS: " << rps << std::endl;
    }

    void TestDecryptAesCbc256(int threadCount, int testDuration)
    {
        atomic_llong decrypt_count = 0;
        atomic_llong decrypt_duration_running_sum = 0;

        // create a cipher text and use it for decrypt operation
        SECURITY_STATUS status;
        BYTE plainText[128];
        generateRandomByteArray(128, plainText);
        DWORD plainTextSize = sizeof(plainText);
        DWORD cipherTextSize = 0;
        PBYTE cipherText = NULL;

        constexpr ULONG AES_256_TAG_BYTE_LENGTH = 16;
        constexpr ULONG AES_256_INIT_VECTOR_BYTE_LENGTH = 12;
        constexpr ULONG AES_256_INIT_VECTOR_ULONG_LENGTH = AES_256_INIT_VECTOR_BYTE_LENGTH / sizeof(ULONG);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO AuthCipherModeInfo = { 0 };
        BYTE Tag[AES_256_TAG_BYTE_LENGTH];
        BYTE InitVector[AES_256_INIT_VECTOR_BYTE_LENGTH];
        BCRYPT_INIT_AUTH_MODE_INFO(AuthCipherModeInfo);

        AuthCipherModeInfo.pbNonce = InitVector;
        AuthCipherModeInfo.cbNonce = sizeof(InitVector);
        AuthCipherModeInfo.pbTag = Tag;
        AuthCipherModeInfo.cbTag = sizeof(Tag);

        NCRYPT_CIPHER_PADDING_INFO  paddingInfo;
        paddingInfo.dwFlags = NCRYPT_CIPHER_OTHER_PADDING_FLAG;
        paddingInfo.cbIV = 0;
        paddingInfo.pbIV = NULL;
        paddingInfo.cbOtherInfo = sizeof(AuthCipherModeInfo);
        paddingInfo.pbOtherInfo = (PUCHAR)&AuthCipherModeInfo;
        paddingInfo.cbSize = sizeof(NCRYPT_CIPHER_PADDING_INFO);

        status = NCryptEncrypt(g_hKey, plainText, plainTextSize, &paddingInfo, NULL, 0, &cipherTextSize, NCRYPT_PAD_CIPHER_FLAG);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptEncrypt1 failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            NCryptFreeObject(g_hKey);
            return;
        }

        cipherText = new BYTE[cipherTextSize];
        status = NCryptEncrypt(g_hKey, plainText, plainTextSize, &paddingInfo, cipherText, cipherTextSize, &cipherTextSize, NCRYPT_PAD_CIPHER_FLAG);

        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptEncrypt2 failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            NCryptFreeObject(g_hKey);
            return;
        }

        vector<thread> threads(threadCount);
        for (int idx = 0; idx < threadCount; ++idx)
        {
            threads[idx] = thread([&]() {
                DWORD decryptedSize = 0;
                PBYTE decryptedText = NULL;
                std::chrono::time_point<std::chrono::high_resolution_clock> start_time, end_time;
                std::int64_t execution_time;

                auto loop_start_time = std::chrono::steady_clock::now();
                while (std::chrono::steady_clock::now() - loop_start_time < std::chrono::seconds(testDuration))
                {
                    // Decrypt 
                    start_time = std::chrono::high_resolution_clock::now();
                    status = NCryptDecrypt(g_hKey, cipherText, cipherTextSize, &paddingInfo, NULL, 0, &decryptedSize, NCRYPT_PAD_CIPHER_FLAG);
                    if (status != ERROR_SUCCESS)
                    {
                        wprintf(L"NCryptDecrypt1 failed with %x\n", status);
                        NCryptFreeObject(g_hProvider);
                        NCryptFreeObject(g_hKey);
                        return;
                    }

                    decryptedText = new BYTE[decryptedSize];

                    status = NCryptDecrypt(g_hKey, cipherText, cipherTextSize, &paddingInfo, decryptedText, decryptedSize, &decryptedSize, NCRYPT_PAD_CIPHER_FLAG);
                    if (status != ERROR_SUCCESS)
                    {
                        wprintf(L"NCryptDecrypt2 failed with %x\n", status);
                        NCryptFreeObject(g_hProvider);
                        NCryptFreeObject(g_hKey);
                        return;
                    }

                    delete[] decryptedText;
                    end_time = std::chrono::high_resolution_clock::now();
                    execution_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
                    decrypt_count++;
                    decrypt_duration_running_sum += execution_time;
                }
            });
        }

        for (int idx = 0; idx < threadCount; ++idx)
        {
            threads[idx].join();
        }

        delete[] cipherText;
        // Generate average time report for Decrypt operation
        auto avg_execution_time = calculateAverage1(decrypt_duration_running_sum, decrypt_count);
        auto rps = calculateRps(testDuration, decrypt_count);
        std::cout << "[Decrypt] [AES 256 - CBC] Average execution time: " << avg_execution_time << " microseconds; RPS: " << rps << std::endl;
    }
};

