#pragma once
#include <vector>
#include <iostream>
#include <numeric>
#include <atomic>
#include <random>

static double calculateAverage1(long long total, long long count)
{
    std::cout << "size of execution times vector:" << count << std::endl;
    auto avg_execution_time = static_cast<double>(total) / count;
    return avg_execution_time;
}


static double calculateRps(long long total, long long count)
{
    auto rps = static_cast<double>(count) / total;
    // std::cout << "RPS:" << rps << std::endl;
    return rps;
}

void generateRandomByteArray(int length, BYTE* byteArray) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    // Generate the byte array
    for (int i = 0; i < length; i++) {
        byteArray[i] = static_cast<unsigned char>(dis(gen));
    }
}