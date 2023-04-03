// KeyGaurdPerfTestClient.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#pragma once

#include <iostream>
#include <string>
#include "Rsa2048KeyGuard.h"
#include "Rsa2048Vtpm.h"
#include "Rsa3072KeyGuard.h"
#include "AesCbc256KeyGuard.h"
#include "Ecdsa256KeyGuard.h"
#include "Ecdsa384KeyGuard.h"
#include "AesGcm256NoKg.h"
#include "Ecdsa256Vtpm.h"

#define DEFAULT_THREAD_COUNT 1
#define DEFAULT_TEST_DURATION_IN_SECONDS 120
#define MIN_ARGS 2

int main(int argc, char* argv[])
{
    try
    {
        const char* testName;
        int threadCount = DEFAULT_THREAD_COUNT;
        int testDuration = DEFAULT_TEST_DURATION_IN_SECONDS;

        if (argc < MIN_ARGS)
        {
            throw std::invalid_argument("Invalid number of arguments. Try KeyGuardPerfTestClient <test_name> <thread_count> <test_duration_in_seconds>.\n");
        }
        else
        {
            testName = argv[1];
        }

        if (argc > 2 && std::stoi(argv[2]) > DEFAULT_THREAD_COUNT)
        {
            threadCount = std::stoi(argv[2]);
        }

        if (argc > 3 && std::stoi(argv[3]) > DEFAULT_TEST_DURATION_IN_SECONDS)
        {
            testDuration = std::stoi(argv[3]);
        }

        printf("Executing [ %s ] scenario with [ %d ] concurrent threads for [%d] seconds", testName, threadCount, testDuration);

        if (!_strcmpi(testName, "Rsa2048KeyGuard"))
        {
            Rsa2048KeyGuard obj;
            obj.runTests(threadCount, testDuration);
        }
        else if (!_strcmpi(testName, "Rsa2048Vtpm"))
        {
            Rsa2048Vtpm obj;
            obj.runTests(threadCount, testDuration);
        }
        else if (!_strcmpi(testName, "Rsa3072KeyGuard"))
        {
            Rsa3072KeyGuard obj;
            obj.runTests(threadCount, testDuration);
        }
        else if (!_strcmpi(testName, "AesCbc256KeyGuard"))
        {
            AesCbc256KeyGuard obj;
            obj.runTests(threadCount, testDuration);
        }
        else if (!_strcmpi(testName, "AesGcm256NoKg"))
        {
            AesGcm256NoKg obj;
            obj.runTests(threadCount, testDuration);
        }
        else if (!_strcmpi(testName, "Ecdsa256KeyGuard"))
        {
            Ecdsa256KeyGuard obj;
            obj.runTests(threadCount, testDuration);
        }
        else if (!_strcmpi(testName, "Ecdsa256Vtpm"))
        {
            Ecdsa256Vtpm obj;
            obj.runTests(threadCount, testDuration);
        }
        else if (!_strcmpi(testName, "Ecdsa384KeyGuard"))
        {
            Ecdsa384KeyGuard obj;
            obj.runTests(threadCount, testDuration);
        }
        else
        {
            fprintf(stderr, "Incorrect Input Params");
        }

        return EXIT_SUCCESS;
    }
    catch (const std::exception& e)
    {
        printf("Error performing request: '%s'.\n", e.what());
        return EXIT_FAILURE;
    }
}