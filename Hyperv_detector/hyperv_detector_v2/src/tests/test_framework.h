/*
 * Hyper-V Detector Test Framework
 * Simple test framework for running detection method tests
 */
#pragma once
#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>

/* Test result codes */
typedef enum _TEST_RESULT {
    TEST_PASS = 0,
    TEST_FAIL = 1,
    TEST_SKIP = 2,
    TEST_ERROR = 3
} TEST_RESULT;

/* Test case structure */
typedef struct _TEST_CASE {
    const char* name;
    const char* category;
    TEST_RESULT (*testFunc)(char* message, size_t messageSize);
    BOOL requiresAdmin;
    BOOL requiresHypervisor;
} TEST_CASE, *PTEST_CASE;

/* Test statistics */
typedef struct _TEST_STATS {
    int total;
    int passed;
    int failed;
    int skipped;
    int errors;
    DWORD startTime;
    DWORD endTime;
} TEST_STATS, *PTEST_STATS;

/* Global test stats */
static TEST_STATS g_testStats = {0};

/* Console colors */
#define COLOR_RESET   "\033[0m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_RED     "\033[31m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"

/* Enable ANSI colors on Windows */
static void EnableConsoleColors(void)
{
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
    SetConsoleMode(hOut, dwMode);
}

/* Print test result */
static void PrintTestResult(const char* name, TEST_RESULT result, const char* message, DWORD elapsed)
{
    const char* resultStr;
    const char* color;
    
    switch (result) {
        case TEST_PASS:
            resultStr = "PASS";
            color = COLOR_GREEN;
            g_testStats.passed++;
            break;
        case TEST_FAIL:
            resultStr = "FAIL";
            color = COLOR_RED;
            g_testStats.failed++;
            break;
        case TEST_SKIP:
            resultStr = "SKIP";
            color = COLOR_YELLOW;
            g_testStats.skipped++;
            break;
        default:
            resultStr = "ERROR";
            color = COLOR_RED;
            g_testStats.errors++;
            break;
    }
    
    g_testStats.total++;
    
    printf("  [%s%s%s] %-45s (%3lu ms)", 
        color, resultStr, COLOR_RESET, 
        name, elapsed);
    
    if (message && message[0]) {
        printf(" - %s", message);
    }
    printf("\n");
}

/* Print category header */
static void PrintCategoryHeader(const char* category)
{
    printf("\n%s=== %s ===%s\n", COLOR_CYAN, category, COLOR_RESET);
}

/* Print test summary */
static void PrintTestSummary(void)
{
    DWORD totalTime = g_testStats.endTime - g_testStats.startTime;
    
    printf("\n%s========================================%s\n", COLOR_WHITE, COLOR_RESET);
    printf("               TEST SUMMARY\n");
    printf("%s========================================%s\n", COLOR_WHITE, COLOR_RESET);
    printf("  Total:   %d\n", g_testStats.total);
    printf("  %sPassed:  %d%s\n", COLOR_GREEN, g_testStats.passed, COLOR_RESET);
    printf("  %sFailed:  %d%s\n", g_testStats.failed > 0 ? COLOR_RED : COLOR_WHITE, g_testStats.failed, COLOR_RESET);
    printf("  %sSkipped: %d%s\n", COLOR_YELLOW, g_testStats.skipped, COLOR_RESET);
    printf("  %sErrors:  %d%s\n", g_testStats.errors > 0 ? COLOR_RED : COLOR_WHITE, g_testStats.errors, COLOR_RESET);
    printf("  Time:    %lu ms\n", totalTime);
    printf("%s========================================%s\n", COLOR_WHITE, COLOR_RESET);
    
    if (g_testStats.failed == 0 && g_testStats.errors == 0) {
        printf("  %sAll tests passed!%s\n", COLOR_GREEN, COLOR_RESET);
    } else {
        printf("  %sSome tests failed or had errors%s\n", COLOR_RED, COLOR_RESET);
    }
    printf("\n");
}

/* Run a single test */
static void RunTest(PTEST_CASE test, BOOL isAdmin, BOOL hasHypervisor)
{
    char message[512] = {0};
    DWORD start, end;
    TEST_RESULT result;
    
    /* Check prerequisites */
    if (test->requiresAdmin && !isAdmin) {
        snprintf(message, sizeof(message), "Requires administrator privileges");
        PrintTestResult(test->name, TEST_SKIP, message, 0);
        return;
    }
    
    if (test->requiresHypervisor && !hasHypervisor) {
        snprintf(message, sizeof(message), "Requires hypervisor presence");
        PrintTestResult(test->name, TEST_SKIP, message, 0);
        return;
    }
    
    /* Run the test */
    start = GetTickCount();
    __try {
        result = test->testFunc(message, sizeof(message));
    }
    __except(EXCEPTION_EXECUTE_HANDLER) {
        result = TEST_ERROR;
        snprintf(message, sizeof(message), "Exception 0x%08X", GetExceptionCode());
    }
    end = GetTickCount();
    
    PrintTestResult(test->name, result, message, end - start);
}

/* JSON output for automated processing */
static void PrintJsonResult(const char* configName)
{
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    char timeStr[64];
    strftime(timeStr, sizeof(timeStr), "%Y-%m-%dT%H:%M:%S", tm_info);
    
    printf("\n{\n");
    printf("  \"config\": \"%s\",\n", configName);
    printf("  \"timestamp\": \"%s\",\n", timeStr);
    printf("  \"total\": %d,\n", g_testStats.total);
    printf("  \"passed\": %d,\n", g_testStats.passed);
    printf("  \"failed\": %d,\n", g_testStats.failed);
    printf("  \"skipped\": %d,\n", g_testStats.skipped);
    printf("  \"errors\": %d,\n", g_testStats.errors);
    printf("  \"duration_ms\": %lu,\n", g_testStats.endTime - g_testStats.startTime);
    printf("  \"success\": %s\n", (g_testStats.failed == 0 && g_testStats.errors == 0) ? "true" : "false");
    printf("}\n");
}

#endif /* TEST_FRAMEWORK_H */
