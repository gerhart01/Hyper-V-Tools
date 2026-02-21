# ==============================================================================
# Module:      Hvlib.Constants.ps1
# Version:     1.1.1
# Description: Constants and enumerations for Hvlib PowerShell module
# ==============================================================================
# Change Log:
# 1.1.1 - Bug fix: Removed DEFAULT_DLL_PATH and Export-ModuleMember
# 1.1.0 - Initial refactored version with extracted constants
# ==============================================================================

# Module configuration
$Script:MODULE_NAME = "Hvlib"
$Script:MODULE_VERSION = "1.1.1"

# Console colors
$Script:COLOR_SUCCESS = "DarkMagenta"
$Script:COLOR_INFO = "Cyan"
$Script:COLOR_WARNING = "Yellow"
$Script:COLOR_ERROR = "Red"

# Message templates
$Script:MSG_LIBRARY_NOT_FOUND = "Library not found at path: {0}"
$Script:MSG_LIBRARY_LOADED = "Library loaded successfully: {0}"
$Script:MSG_OPERATION_SUCCESS = "Operation completed successfully"
$Script:MSG_OPERATION_FAILED = "Operation failed"
$Script:MSG_FILE_NOT_FOUND = "File not found: {0}"
$Script:MSG_VM_COUNT = "Found {0} virtual machine(s)"
$Script:MSG_VM_NOT_FOUND = "Virtual machine '{0}' not found"
$Script:MSG_VM_FOUND = "Virtual machine '{0}' found with handle: 0x{1:X}"
$Script:MSG_PARTITION_SELECTED = "Partition selected: handle 0x{0:X}"
$Script:MSG_PARTITION_CLOSED = "Partition closed: handle 0x{0:X}"
$Script:MSG_ALL_PARTITIONS_CLOSED = "All partitions closed"
$Script:MSG_MEMORY_READ_SUCCESS = "Read {0} bytes from address 0x{1:X}"
$Script:MSG_MEMORY_WRITE_SUCCESS = "Wrote {0} bytes to address 0x{1:X}"
$Script:MSG_MEMORY_OPERATION_FAILED = "Memory operation failed"
$Script:MSG_PROCESSES_FOUND = "Found {0} process(es)"
$Script:MSG_CR3_RETRIEVED = "CR3 = 0x{0:X} for PID: {1}"
$Script:MSG_DATA_RETRIEVED = "Data retrieved for {0}"
$Script:MSG_INVALID_HANDLE = "Invalid partition handle: {0}"
$Script:MSG_NULL_RESULT = "Operation returned null result"

# Special PID values for CR3 retrieval
$Script:PID_HYPERVISOR = 0xFFFFFFFF
$Script:PID_KERNEL = 0xFFFFFFFE

# Memory operation defaults
$Script:DEFAULT_PAGE_SIZE = 0x1000
$Script:LARGE_PAGE_SIZE = 0x200000
