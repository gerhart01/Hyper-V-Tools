#pragma once
#ifndef HYPERV_DETECTOR_H
#define HYPERV_DETECTOR_H

#include "../common/common.h"
#include "../common/shared_structs.h"

// Function declarations
DWORD CheckCpuidHyperV(PDETECTION_RESULT result);
DWORD CheckRegistryHyperV(PDETECTION_RESULT result);
DWORD CheckFilesHyperV(PDETECTION_RESULT result);
DWORD CheckServicesHyperV(PDETECTION_RESULT result);
DWORD CheckDevicesHyperV(PDETECTION_RESULT result);
DWORD CheckBiosHyperV(PDETECTION_RESULT result);
DWORD CheckProcessesHyperV(PDETECTION_RESULT result);
DWORD CheckWindowsObjectsHyperV(PDETECTION_RESULT result);
DWORD CheckNestedHyperV(PDETECTION_RESULT result);
DWORD CheckWindowsSandbox(PDETECTION_RESULT result);
DWORD CheckDockerHyperV(PDETECTION_RESULT result);
DWORD CheckRemovedHyperV(PDETECTION_RESULT result);

// Helper functions
void ExecuteCpuid(DWORD function, PCPUID_RESULT result);
BOOL IsRunningAsAdmin();
void AppendToDetails(PDETECTION_RESULT result, const char* format, ...);

#endif // HYPERV_DETECTOR_H