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

class Rsa3072KeyGuard
{
public:
    NCRYPT_PROV_HANDLE  g_hProvider = 0;
    NCRYPT_KEY_HANDLE g_hKey = 0;
    DWORD keyLength = 3072;

    void runTests(int threadCount, int testDuration)
    {
        // Initial setup - open a handle to the KSP and create a RSA 3072 persisted key for encrypt/decrypt operations
        SECURITY_STATUS status;
        status = NCryptOpenStorageProvider(&g_hProvider, MS_KEY_STORAGE_PROVIDER, 0); // MS_PLATFORM_CRYPTO_PROVIDER, MS_KEY_STORAGE_PROVIDER
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptCreatePersistedKey failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            return;
        }

        // Generate the key
        status = NCryptCreatePersistedKey(g_hProvider, &g_hKey, NCRYPT_RSA_ALGORITHM, NULL, 0, NCRYPT_USE_VIRTUAL_ISOLATION_FLAG); // NCRYPT_MACHINE_KEY_FLAG, NCRYPT_USE_VIRTUAL_ISOLATION_FLAG
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

        status = NCryptFinalizeKey(g_hKey, 0);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptFinalizeKey failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            NCryptFreeObject(g_hKey);
            return;
        }

        wprintf(L"Created a persisted Key Guard key!\n");

        // run sub-scenarios
        std::cout << "\n**** Executing Encrypt/Decrypt using RSA 3072 PKCS1.5 ****" << std::endl;
        TestEncryptRsa3072(threadCount, testDuration);
        TestDecryptRsa3072(threadCount, testDuration);
        TestSignRsa3072(threadCount, testDuration);
        std::cout << "**********************************************************\n" << std::endl;

        // cleanup
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
    void TestEncryptRsa3072(int threadCount, int testDuration)
    {
        atomic_llong encrypt_count = 0;
        atomic_llong encrypt_duration_running_sum = 0;

        vector<thread> threads(threadCount);

        for (int idx = 0; idx < threadCount; ++idx)
        {
            threads[idx] = thread([&]() {
                SECURITY_STATUS status;
                BYTE plainText[128];
                DWORD plainTextSize = sizeof(plainText);
                generateRandomByteArray(128, plainText);
                DWORD cipherTextSize = 0;
                PBYTE cipherText = NULL;
                DWORD decryptedSize = 0;
                PBYTE decryptedText = NULL;
                std::chrono::time_point<std::chrono::high_resolution_clock> start_time, end_time;
                std::int64_t execution_time;

                auto loop_start_time = std::chrono::steady_clock::now();
                while (std::chrono::steady_clock::now() - loop_start_time < std::chrono::seconds(testDuration))
                {
                    start_time = std::chrono::high_resolution_clock::now();

                    // Determine the size of the encrypted data
                    status = NCryptEncrypt(g_hKey, plainText, plainTextSize, NULL, NULL, 0, &cipherTextSize, NCRYPT_PAD_PKCS1_FLAG);
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
                    status = NCryptEncrypt(g_hKey, plainText, plainTextSize, NULL, cipherText, cipherTextSize, &cipherTextSize, NCRYPT_PAD_PKCS1_FLAG);

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
        std::cout << "[Encrypt] [RSA 3072 - PKCS] Average execution time: " << avg_execution_time << " microseconds; RPS: " << rps << std::endl;
    }

    void TestDecryptRsa3072(int threadCount, int testDuration)
    {
        atomic_llong decrypt_count = 0;
        atomic_llong decrypt_duration_running_sum = 0;

        // create a cipher text and use it for decryption operations
        SECURITY_STATUS status;
        BYTE plainText[128];
        DWORD plainTextSize = sizeof(plainText);
        generateRandomByteArray(128, plainText);
        DWORD cipherTextSize = 0;
        PBYTE cipherText = NULL;
        status = NCryptEncrypt(g_hKey, plainText, plainTextSize, NULL, NULL, 0, &cipherTextSize, NCRYPT_PAD_PKCS1_FLAG);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptEncrypt1 failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            NCryptFreeObject(g_hKey);
            return;
        }
        cipherText = new BYTE[cipherTextSize];
        status = NCryptEncrypt(g_hKey, plainText, plainTextSize, NULL, cipherText, cipherTextSize, &cipherTextSize, NCRYPT_PAD_PKCS1_FLAG);

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
                    status = NCryptDecrypt(g_hKey, cipherText, cipherTextSize, NULL, NULL, 0, &decryptedSize, NCRYPT_PAD_PKCS1_FLAG);
                    if (status != ERROR_SUCCESS)
                    {
                        wprintf(L"NCryptDecrypt1 failed with %x\n", status);
                        NCryptFreeObject(g_hProvider);
                        NCryptFreeObject(g_hKey);
                        return;
                    }

                    decryptedText = new BYTE[decryptedSize];

                    status = NCryptDecrypt(g_hKey, cipherText, cipherTextSize, NULL, decryptedText, decryptedSize, &decryptedSize, NCRYPT_PAD_PKCS1_FLAG);
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
        std::cout << "[Decrypt] [RSA 3072 - PKCS] Average execution time: " << avg_execution_time << " microseconds; RPS: " << rps << std::endl;
    }

    void TestSignRsa3072(int threadCount, int testDuration)
    {
        atomic_llong sign_count = 0;
        atomic_llong sign_duration_running_sum = 0;
        vector<thread> threads(threadCount);

        for (int idx = 0; idx < threadCount; ++idx)
        {
            threads[idx] = thread([&]() {
                SECURITY_STATUS status;
                DWORD cbSignature = 0;
                BYTE* pbSignature = NULL;

                BYTE hash[32];
                generateRandomByteArray(32, hash);

                BCRYPT_PSS_PADDING_INFO PSSPadding;
                PSSPadding.pszAlgId = BCRYPT_SHA256_ALGORITHM;
                PSSPadding.cbSalt = 32;

                std::chrono::time_point<std::chrono::high_resolution_clock> start_time, end_time;
                std::int64_t execution_time;

                auto loop_start_time = std::chrono::steady_clock::now();
                while (std::chrono::steady_clock::now() - loop_start_time < std::chrono::seconds(testDuration))
                {
                    start_time = std::chrono::high_resolution_clock::now();

                    // Sign the hash
                    status = NCryptSignHash(g_hKey, &PSSPadding, hash, sizeof(hash), NULL, 0, &cbSignature, BCRYPT_PAD_PSS);
                    if (status != ERROR_SUCCESS) {
                        printf("NCryptSignHash1 failed: %08X\n", status);
                        NCryptFreeObject(g_hProvider);
                        NCryptFreeObject(g_hKey);
                        return;
                    }

                    // Allocate memory for the signature
                    pbSignature = new BYTE[cbSignature];

                    // Sign the hash again, this time with the allocated buffer
                    status = NCryptSignHash(g_hKey, &PSSPadding, hash, sizeof(hash), pbSignature, cbSignature, &cbSignature, BCRYPT_PAD_PSS);
                    if (status != ERROR_SUCCESS) {
                        printf("NCryptSignHash2 failed: %08X\n", status);
                        NCryptFreeObject(g_hProvider);
                        NCryptFreeObject(g_hKey);
                        return;
                    }

                    delete[] pbSignature;
                    end_time = std::chrono::high_resolution_clock::now();
                    execution_time = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time).count();
                    sign_count++;
                    sign_duration_running_sum += execution_time;
                }
            });
        }

        for (int idx = 0; idx < threadCount; ++idx)
        {
            threads[idx].join();
        }

        // Generate average time report for Encrypt operation
        double avg_execution_time = calculateAverage1(sign_duration_running_sum, sign_count);
        double rps = calculateRps(testDuration, sign_count);
        std::cout << "[Sign] [RSA 3072 - PKCS] Average execution time: " << avg_execution_time << " microseconds; RPS: " << rps << std::endl;
    }
};
