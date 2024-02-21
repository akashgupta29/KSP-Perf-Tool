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

class Ecdsa384KeyGuard
{
public:
    NCRYPT_PROV_HANDLE  g_hProvider = 0;
    NCRYPT_KEY_HANDLE g_hKey = 0;
    DWORD keyLength = 384;

    void runTests(int threadCount, int testDuration)
    {
        SECURITY_STATUS status;

        // Initial setup - open a handle to the KSP and create a persisted key 
        // MS_PLATFORM_CRYPTO_PROVIDER => TPM, MS_KEY_STORAGE_PROVIDER => KG
        status = NCryptOpenStorageProvider(&g_hProvider, MS_KEY_STORAGE_PROVIDER, 0);
        if (status != ERROR_SUCCESS)
        {
            wprintf(L"NCryptCreatePersistedKey failed with %x\n", status);
            NCryptFreeObject(g_hProvider);
            return;
        }

        // Generate the key
        status = NCryptCreatePersistedKey(g_hProvider, &g_hKey, NCRYPT_ECDSA_P384_ALGORITHM, NULL, 0, NCRYPT_USE_VIRTUAL_ISOLATION_FLAG); // NCRYPT_MACHINE_KEY_FLAG, NCRYPT_USE_VIRTUAL_ISOLATION_FLAG
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

        wprintf(L"\nCreated a persisted ECDSA P384 key!\n");

        // run sub-scenarios
        std::cout << "\n**** Executing Sign operation using ECDSA P384 ****" << std::endl;
        TestSignEcdsaP384(threadCount, testDuration);
        std::cout << "*****************************************************\n" << std::endl;

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
    void TestSignEcdsaP384(int threadCount, int testDuration)
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

                // Hash data to sign
                BYTE hash[32];
                generateRandomByteArray(32, hash);

                std::chrono::time_point<std::chrono::high_resolution_clock> start_time, end_time;
                std::int64_t execution_time;

                auto loop_start_time = std::chrono::steady_clock::now();
                while (std::chrono::steady_clock::now() - loop_start_time < std::chrono::seconds(testDuration))
                {
                    start_time = std::chrono::high_resolution_clock::now();

                    // Sign the hash
                    status = NCryptSignHash(g_hKey, NULL, hash, sizeof(hash), NULL, 0, &cbSignature, 0);
                    if (status != ERROR_SUCCESS) {
                        printf("NCryptSignHash1 failed: %08X\n", status);
                        NCryptFreeObject(g_hProvider);
                        NCryptFreeObject(g_hKey);
                        return;
                    }

                    // Allocate memory for the signature
                    pbSignature = new BYTE[cbSignature];

                    // Sign the hash again, this time with the allocated buffer
                    status = NCryptSignHash(g_hKey, NULL, hash, sizeof(hash), pbSignature, cbSignature, &cbSignature, 0);
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

        // Generate average time report for Sign operation
        double avg_execution_time = calculateAverage1(sign_duration_running_sum, sign_count);
        double rps = calculateRps(testDuration, sign_count);
        std::cout << "[Sign] [ECDSA - P256] Average execution time: " << avg_execution_time << " microseconds; RPS: " << rps << std::endl;
    }
};

