/**
 * timing_checks.c - Timing-based Hyper-V detection
 * 
 * Uses various timing analysis techniques to detect virtualization:
 * - RDTSC timing discrepancies
 * - CPUID timing analysis
 * - I/O port timing
 * - Interrupt timing analysis
 */

#include "hyperv_detector.h"

// Detection flag for timing
#define HYPERV_DETECTED_TIMING 0x00010000

// Number of timing samples
#define TIMING_SAMPLES 1000
#define TIMING_THRESHOLD_RDTSC 500      // Cycles threshold for RDTSC
#define TIMING_THRESHOLD_CPUID 10000    // Cycles threshold for CPUID

#if ARCH_X86_OR_X64
// Read Time-Stamp Counter
static inline UINT64 ReadTSC(void) {
    return __rdtsc();
}

// Read TSC with serialization (more accurate)
static inline UINT64 ReadTSCP(UINT32* aux) {
    /* MSVC intrinsic for rdtscp */
    return __rdtscp(aux);
}

// CPUID-based serialization before RDTSC
static inline UINT64 ReadTSCSerialized(void) {
    int cpuInfo[4];
    __cpuid(cpuInfo, 0);  // Serialize
    return __rdtsc();
}
#endif /* ARCH_X86_OR_X64 */

typedef struct _TIMING_STATS {
    UINT64 min;
    UINT64 max;
    UINT64 avg;
    UINT64 variance;
    DWORD outliers;
} TIMING_STATS, *PTIMING_STATS;

static void CalculateStats(UINT64* samples, DWORD count, PTIMING_STATS stats) {
    if (count == 0) return;
    
    // Calculate min, max, sum
    stats->min = ULLONG_MAX;
    stats->max = 0;
    UINT64 sum = 0;
    
    for (DWORD i = 0; i < count; i++) {
        if (samples[i] < stats->min) stats->min = samples[i];
        if (samples[i] > stats->max) stats->max = samples[i];
        sum += samples[i];
    }
    
    stats->avg = sum / count;
    
    // Calculate variance
    UINT64 varSum = 0;
    stats->outliers = 0;
    
    for (DWORD i = 0; i < count; i++) {
        INT64 diff = (INT64)samples[i] - (INT64)stats->avg;
        varSum += (UINT64)(diff * diff);
        
        // Count outliers (more than 3x average)
        if (samples[i] > stats->avg * 3) {
            stats->outliers++;
        }
    }
    
    stats->variance = varSum / count;
}

#if ARCH_X86_OR_X64
// Test 1: RDTSC timing consistency
static DWORD TestRDTSCTiming(PDETECTION_RESULT result) {
    DWORD detected = 0;
    UINT64* samples = (UINT64*)malloc(TIMING_SAMPLES * sizeof(UINT64));
    TIMING_STATS stats = {0};
    
    if (!samples) return 0;
    
    // Warm up CPU
    for (int i = 0; i < 100; i++) {
        volatile UINT64 dummy = ReadTSC();
        (void)dummy;
    }
    
    // Collect samples
    for (int i = 0; i < TIMING_SAMPLES; i++) {
        UINT64 start = ReadTSCSerialized();
        UINT64 end = ReadTSCSerialized();
        samples[i] = end - start;
    }
    
    CalculateStats(samples, TIMING_SAMPLES, &stats);
    
    AppendToDetails(result, "Timing: RDTSC - Min: %llu, Max: %llu, Avg: %llu, Outliers: %d\n",
                   stats.min, stats.max, stats.avg, stats.outliers);
    
    // High variance or many outliers indicate VM
    if (stats.max - stats.min > TIMING_THRESHOLD_RDTSC || stats.outliers > TIMING_SAMPLES / 10) {
        detected |= HYPERV_DETECTED_TIMING;
        AppendToDetails(result, "Timing: RDTSC variance indicates possible VM\n");
    }
    
    // Average cycle count > threshold
    if (stats.avg > 50) {
        detected |= HYPERV_DETECTED_TIMING;
        AppendToDetails(result, "Timing: High RDTSC overhead (%llu cycles avg) indicates VM\n", stats.avg);
    }
    
    free(samples);
    return detected;
}

// Test 2: CPUID execution timing
static DWORD TestCPUIDTiming(PDETECTION_RESULT result) {
    DWORD detected = 0;
    UINT64* samples = (UINT64*)malloc(TIMING_SAMPLES * sizeof(UINT64));
    TIMING_STATS stats = {0};
    int cpuInfo[4];
    
    if (!samples) return 0;
    
    // Warm up
    for (int i = 0; i < 100; i++) {
        __cpuid(cpuInfo, 0);
    }
    
    // Test CPUID leaf 0 timing
    for (int i = 0; i < TIMING_SAMPLES; i++) {
        UINT64 start = ReadTSCSerialized();
        __cpuid(cpuInfo, 0);
        UINT64 end = ReadTSCSerialized();
        samples[i] = end - start;
    }
    
    CalculateStats(samples, TIMING_SAMPLES, &stats);
    
    AppendToDetails(result, "Timing: CPUID(0) - Min: %llu, Max: %llu, Avg: %llu, Outliers: %d\n",
                   stats.min, stats.max, stats.avg, stats.outliers);
    
    // Test hypervisor CPUID timing (if hypervisor present)
    __cpuid(cpuInfo, 1);
    if (cpuInfo[2] & (1 << 31)) {
        // Hypervisor present, test hypervisor CPUID leaves
        for (int i = 0; i < TIMING_SAMPLES; i++) {
            UINT64 start = ReadTSCSerialized();
            __cpuid(cpuInfo, 0x40000000);  // Hypervisor leaf
            UINT64 end = ReadTSCSerialized();
            samples[i] = end - start;
        }
        
        TIMING_STATS hvStats = {0};
        CalculateStats(samples, TIMING_SAMPLES, &hvStats);
        
        AppendToDetails(result, "Timing: CPUID(0x40000000) - Min: %llu, Max: %llu, Avg: %llu\n",
                       hvStats.min, hvStats.max, hvStats.avg);
        
        // Hypervisor CPUID typically takes longer
        if (hvStats.avg > stats.avg * 2) {
            detected |= HYPERV_DETECTED_TIMING;
            AppendToDetails(result, "Timing: Hypervisor CPUID overhead detected\n");
        }
    }
    
    // High CPUID timing indicates VM
    if (stats.avg > TIMING_THRESHOLD_CPUID) {
        detected |= HYPERV_DETECTED_TIMING;
        AppendToDetails(result, "Timing: High CPUID execution time indicates VM\n");
    }
    
    free(samples);
    return detected;
}

// Test 3: VM Exit detection via privileged instruction timing
static DWORD TestVMExitTiming(PDETECTION_RESULT result) {
    DWORD detected = 0;
    UINT64* samples = (UINT64*)malloc(TIMING_SAMPLES * sizeof(UINT64));
    TIMING_STATS normalStats = {0};
    TIMING_STATS privilegedStats = {0};
    
    if (!samples) return 0;
    
    // Baseline: Measure simple arithmetic
    for (int i = 0; i < TIMING_SAMPLES; i++) {
        UINT64 start = ReadTSCSerialized();
        volatile int x = 1;
        x = x + x;
        x = x * x;
        UINT64 end = ReadTSCSerialized();
        samples[i] = end - start;
    }
    CalculateStats(samples, TIMING_SAMPLES, &normalStats);
    
    // Measure CPUID (causes VM exit in most hypervisors)
    int cpuInfo[4];
    for (int i = 0; i < TIMING_SAMPLES; i++) {
        UINT64 start = ReadTSCSerialized();
        __cpuid(cpuInfo, 0x80000000);  // Extended CPUID
        UINT64 end = ReadTSCSerialized();
        samples[i] = end - start;
    }
    CalculateStats(samples, TIMING_SAMPLES, &privilegedStats);
    
    AppendToDetails(result, "Timing: Arithmetic baseline avg: %llu cycles\n", normalStats.avg);
    AppendToDetails(result, "Timing: Privileged instruction avg: %llu cycles\n", privilegedStats.avg);
    
    // In VM, ratio should be much higher
    UINT64 ratio = (normalStats.avg > 0) ? (privilegedStats.avg / normalStats.avg) : 0;
    AppendToDetails(result, "Timing: Privileged/Normal ratio: %llu\n", ratio);
    
    if (ratio > 100) {
        detected |= HYPERV_DETECTED_TIMING;
        AppendToDetails(result, "Timing: High VM exit cost detected (ratio: %llu)\n", ratio);
    }
    
    free(samples);
    return detected;
}

// Test 4: Interrupt timing analysis
static DWORD TestInterruptTiming(PDETECTION_RESULT result) {
    DWORD detected = 0;
    UINT64 startTsc, endTsc;
    LARGE_INTEGER freq, start, end;
    
    if (!QueryPerformanceFrequency(&freq)) {
        return 0;
    }
    
    // Measure correlation between TSC and QPC
    QueryPerformanceCounter(&start);
    startTsc = ReadTSC();
    
    // Wait a bit
    Sleep(10);
    
    QueryPerformanceCounter(&end);
    endTsc = ReadTSC();
    
    UINT64 tscDelta = endTsc - startTsc;
    LONGLONG qpcDelta = end.QuadPart - start.QuadPart;
    
    // Calculate expected TSC ticks based on QPC
    // This relies on TSC frequency being available
    UINT64 expectedTsc = (UINT64)((double)qpcDelta / freq.QuadPart * 3000000000.0); // Assume ~3GHz
    
    AppendToDetails(result, "Timing: TSC delta: %llu, QPC delta: %lld\n", tscDelta, qpcDelta);
    
    // In VMs, TSC and QPC might not correlate well
    // This is a heuristic check
    
    return detected;
}
#endif /* ARCH_X86_OR_X64 - timing test functions */

// Main timing check function
DWORD CheckTimingHyperV(PDETECTION_RESULT result) {
#if !ARCH_X86_OR_X64
    AppendToDetails(result, "Timing: RDTSC/CPUID timing not available on ARM64\n");
    return 0;
#else
    DWORD detected = 0;

    AppendToDetails(result, "Timing: Starting timing-based detection...\n");

    // Set thread priority high for accurate timing
    HANDLE hThread = GetCurrentThread();
    int oldPriority = GetThreadPriority(hThread);
    SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

    // Pin to single CPU for consistent timing
    DWORD_PTR oldAffinity = SetThreadAffinityMask(hThread, 1);

    detected |= TestRDTSCTiming(result);
    detected |= TestCPUIDTiming(result);
    detected |= TestVMExitTiming(result);
    detected |= TestInterruptTiming(result);

    // Restore thread settings
    SetThreadAffinityMask(hThread, oldAffinity);
    SetThreadPriority(hThread, oldPriority);

    return detected;
#endif /* ARCH_X86_OR_X64 */
}
