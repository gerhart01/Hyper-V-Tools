#!/usr/bin/env python3
"""
IDA Python 3.12+ Hyper-V Hypercall Extractor

Extracts hypercall information from Hyper-V related modules using Python.
Supports: winhvr.sys, winhv.sys, securekernel.exe, ntoskrnl.exe

Author: Gerhart (@gerhart_x)
License: GPL3
Version: 3.0.0
"""

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Union, Any, NamedTuple

import idc
import idautils
import ida_xref
import ida_auto
import ida_nalt
import ida_hexrays
import ida_funcs
import ida_name


@dataclass(frozen=True)
class Config:
    """Immutable configuration for hypercall extraction"""
    output_dir: Path = field(default_factory=lambda: Path(__file__).parent / "hvcalls_json_files")
    unknown_dir: Path = field(default_factory=lambda: Path(__file__).parent / "hvcalls_json_files" / "unknown")
    duplicate_prefix: int = 0xFFFF00000000

    def __post_init__(self):
        """Validate configuration after initialization"""
        if self.duplicate_prefix <= 0:
            raise ValueError("duplicate_prefix must be positive")


class HypercallEntry(NamedTuple):
    """Immutable hypercall entry"""
    id: Union[int, str]
    name: str
    decompiled_code: str = ""


@dataclass
class HardcodedHypercalls:
    """Container for hardcoded hypercall definitions with validation"""
    
    KNOWN_VERSIONS: Dict[str, Dict[int, str]] = field(default_factory=lambda: {
        "10.0.19041.1052": {
            0x7: "HvlpCondenseMicrocode",
            0x48: "HvlpDepositPages"
        },
        "10.0.20298.1": {
            0x2: "HvlpSlowFlushListTb", 0x3: "HvlpSlowFlushListTb",
            0x13: "HvlpSlowFlushAddressSpaceTbEx", 0x14: "HvlpSlowFlushListTbEx",
            0x15: "HvlpSlowSendSyntheticClusterIpiEx", 0x48: "HvlMapGpaPages",
            0x4E: "HvlpCreateRootVirtualProcessor", 0x6E: "HvlMapSparseGpaPages",
            0x7C: "HvlMapDeviceInterrupt", 0x7F: "HvlRetargetDeviceInterrupt",
            0x82: "HvlRegisterDeviceId", 0x88: "HvlLpReadMultipleMsr",
            0x89: "HvlLpWriteMultipleMsr", 0xA1: "HvlpSlowFlushPasidAddressList",
            0xA6: "HvlpSlowAcknowledgePageRequest", 0xB3: "HvlDmaMapDeviceLogicalRange",
            0xBC: "HvlpAddRemovePhysicalMemory", 0xC7: "HvlDmaMapDeviceSparsePages",
            0xC8: "HvlDmaUnmapDeviceSparsePages", 0xCA: "HvlGetSparseGpaPagesAccessState",
            0xDB: "HvlChangeIsolatedMemoryVisibility"
        },
        "10.0.20344.1": {
            0x7: "HvlpDynamicUpdateMicrocode", 0x10013: "HvlpFastFlushAddressSpaceTbEx",
            0x10014: "HvlpFastFlushListTbEx", 0x8003: "HvlNotifyPageHeat"
        }
    })
    
    def find_by_name(self, name: str) -> Optional[int]:
        """Find hypercall ID by function name across all versions"""
        if not name or not isinstance(name, str):
            return None
            
        for version_map in self.KNOWN_VERSIONS.values():
            for hv_id, hv_name in version_map.items():
                if hv_name == name:
                    return hv_id
        return None


class FileOperations:
    """Handles file operations with proper validation"""
    
    @staticmethod
    def ensure_directories(*paths: Path) -> None:
        """Create directories if they don't exist with validation"""
        for path in paths:
            if not isinstance(path, Path):
                raise TypeError(f"Expected Path, got {type(path)}")
            path.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def save_json(filepath: Path, data: Dict[str, Any]) -> bool:
        """Save dictionary to JSON file with validation"""
        if not isinstance(filepath, Path) or not data:
            return False
            
        if not filepath.parent.exists():
            FileOperations.ensure_directories(filepath.parent)
            
        try:
            filepath.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
            print(f"Saved: {filepath}")
            return True
        except (OSError, ValueError) as e:
            print(f"Failed to save {filepath}: {e}")
            return False

    @staticmethod
    def load_json(filepath: Path) -> Optional[Dict[str, Any]]:
        """Load dictionary from JSON file with validation"""
        if not isinstance(filepath, Path) or not filepath.exists():
            return None
            
        try:
            return json.loads(filepath.read_text(encoding='utf-8'))
        except (OSError, json.JSONDecodeError) as e:
            print(f"Failed to load {filepath}: {e}")
            return None

    @staticmethod
    def get_idb_name() -> str:
        """Get IDB filename with fallback"""
        try:
            import ida_helper
            name = ida_helper.get_idb_name()
            return name if name else Path(ida_nalt.get_input_file_path()).name
        except ImportError:
            return Path(ida_nalt.get_input_file_path()).name

    @staticmethod
    def get_file_version() -> str:
        """Get PE file version with validation"""
        try:
            from pefile import PE
            
            filepath = ida_nalt.get_input_file_path()
            if not filepath or not Path(filepath).exists():
                return "unknown"
                
            pe = PE(filepath)
            if not (hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO):
                return "unknown"
                
            verinfo = pe.VS_FIXEDFILEINFO[0]
            return f"{verinfo.ProductVersionMS >> 16}.{verinfo.ProductVersionMS & 0xFFFF}.{verinfo.ProductVersionLS >> 16}.{verinfo.ProductVersionLS & 0xFFFF}"
        except (ImportError, Exception):
            return "unknown"


class ParameterParser:
    """Modern parameter parsing with comprehensive validation"""
    
    VARIABLE_PATTERNS = re.compile(r'[va]\d+|_[A-Z]+|LL')
    EXPRESSION_PATTERNS = re.compile(r'<<|>>|&|\||\+\+|--|->') 
    NUMERIC_CLEAN = re.compile(r'[^0-9A-Fa-fx]')
    
    @classmethod
    def clean_for_display(cls, param: str) -> str:
        """Clean parameter for display while preserving structure"""
        if not param or not isinstance(param, str):
            return ""
            
        # Remove type suffixes
        cleaned = param.strip()
        for suffix in ["u,", "i64,", ");", ")"]:
            if cleaned.endswith(suffix.rstrip(",")):
                cleaned = cleaned[:-len(suffix.rstrip(","))].strip()
                break
        
        return ' '.join(cleaned.split())

    @classmethod
    def contains_variables(cls, param: str) -> bool:
        """Check if parameter contains variables or complex expressions"""
        if not param:
            return False
        return bool(cls.VARIABLE_PATTERNS.search(param) or cls.EXPRESSION_PATTERNS.search(param))

    @classmethod
    def is_simple_numeric(cls, param: str) -> bool:
        """Check if parameter is a simple numeric value"""
        if not param:
            return False
            
        cleaned = cls.NUMERIC_CLEAN.sub('', param.replace('0x', ''))
        return bool(cleaned) and all(c in "0123456789ABCDEFabcdef" for c in cleaned)

    @classmethod
    def parse_numeric(cls, param: str) -> Optional[int]:
        """Parse numeric value from parameter"""
        if not cls.is_simple_numeric(param):
            return None
            
        cleaned = param.replace("u", "").replace("i64", "").replace("LL", "").replace(" ", "")
        try:
            return int(cleaned, 16 if "0x" in param else 10)
        except ValueError:
            return None

    @classmethod
    def extract_hypercall_id(cls, param: str, function_name: str, hardcoded: HardcodedHypercalls) -> Union[int, str]:
        """Extract hypercall ID with comprehensive validation"""
        if not param or not function_name:
            return "invalid_input"

        display_param = cls.clean_for_display(param)
        
        # Try numeric parsing first
        numeric_id = cls.parse_numeric(param)
        if numeric_id is not None:
            return numeric_id

        # Check for variables/expressions
        if cls.contains_variables(display_param):
            return display_param

        # Try hardcoded lookup
        hardcoded_id = hardcoded.find_by_name(function_name)
        return hardcoded_id if hardcoded_id is not None else display_param


class DecompilerInterface:
    """Interface to IDA Hex-Rays decompiler with validation"""
    
    @staticmethod
    def is_valid_address(address: int) -> bool:
        """Validate if address is decompilable"""
        return address != idc.BADADDR and ida_funcs.get_func(address) is not None

    @staticmethod
    def decompile_function(address: int) -> Optional[str]:
        """Safely decompile function with validation"""
        if not DecompilerInterface.is_valid_address(address):
            return None
            
        try:
            return str(ida_hexrays.decompile(address))
        except Exception:
            return None

    @staticmethod
    def extract_function_parameters(code: str, func_name: str) -> str:
        """Extract function parameters using regex"""
        if not code or not func_name:
            return ""

        pattern = rf"{re.escape(func_name)}\s*\(([^)]*)\)"
        match = re.search(pattern, code)
        return match.group(1).replace('\n', ' ').strip() if match else ""

    @classmethod
    def get_parameter_by_index(cls, code: str, func_name: str, index: int) -> str:
        """Get parameter by index with validation"""
        if index < 0:
            return ""
            
        params = cls.extract_function_parameters(code, func_name)
        if not params:
            return ""
            
        param_list = [p.strip() for p in params.split(',')]
        return param_list[index] if 0 <= index < len(param_list) else ""


class UnknownHypercallResolver:
    """Resolves unknown hypercalls using function body analysis"""
    
    HYPERCALL_FUNCTIONS = [
        "HvcallInitiateHypercall", "HvcallFastExtended", 
        "ShvlpInitiateFastHypercall", "ShvlpInitiateRepListHypercall",
        "WinHvpSimplePoolHypercall_CallViaMacro", "WinHvpRangeRepHypercall",
        "WinHvpSpecialListRepHypercall"
    ]
    
    @classmethod
    def resolve_from_body(cls, param: str, func_name: str, body: str) -> Optional[int]:
        """Resolve parameter to concrete integer value"""
        if not all([param, func_name, body]):
            return None

        # Find matching hypercall in body
        for hv_func in cls.HYPERCALL_FUNCTIONS:
            first_param = cls._extract_first_param_from_calls(body, hv_func)
            if first_param and cls._params_match(param, first_param):
                return cls._resolve_to_concrete_value(first_param, body)
        
        return None

    @staticmethod
    def _extract_first_param_from_calls(code: str, func_name: str) -> Optional[str]:
        """Extract first parameter from function calls"""
        pattern = rf"{re.escape(func_name)}\s*\(\s*([^,)]+)"
        match = re.search(pattern, code)
        return match.group(1).strip() if match else None

    @staticmethod
    def _params_match(param1: str, param2: str) -> bool:
        """Check if parameters match with normalization"""
        normalize = lambda p: re.sub(r'[ui]\d*|LL|\s', '', p.lower())
        return normalize(param1) in normalize(param2) or normalize(param2) in normalize(param1)

    @staticmethod
    def _resolve_to_concrete_value(param: str, body: str) -> Optional[int]:
        """Attempt to resolve parameter to concrete integer"""
        # Try direct numeric conversion
        try:
            cleaned = re.sub(r'[ui]\d*|LL|\s', '', param)
            return int(cleaned, 16 if '0x' in param else 10)
        except ValueError:
            pass

        # Look for variable assignments
        var_name = re.match(r'^([va]\d+)', param)
        if var_name:
            assignment_pattern = rf"{var_name.group(1)}\s*=\s*([^;]+)"
            match = re.search(assignment_pattern, body)
            if match:
                try:
                    value = match.group(1).strip()
                    return int(value, 16 if '0x' in value else 10)
                except ValueError:
                    pass

        return None


class ModuleConfiguration:
    """Configuration for different module types"""
    
    MODULES = {
        "winhvr.sys": [("WinHvpSimplePoolHypercall_CallViaMacro", 1), ("WinHvpRangeRepHypercall", 0), ("WinHvpSpecialListRepHypercall", 0)],
        "winhv.sys": [("WinHvpSimplePoolHypercall_CallViaMacro", 1), ("WinHvpRangeRepHypercall", 0), ("WinHvpSpecialListRepHypercall", 0)],
        "securekernel.exe": [("ShvlpInitiateFastHypercall", 0), ("ShvlpInitiateRepListHypercall", 0)],
        "securekernella57.exe": [("ShvlpInitiateFastHypercall", 0), ("ShvlpInitiateRepListHypercall", 0)],
        "ntoskrnl.exe": [("HvcallFastExtended", 0), ("HvcallInitiateHypercall", 0)],
        "ntkrla57.exe": [("HvcallFastExtended", 0), ("HvcallInitiateHypercall", 0)]
    }

    @classmethod
    def get_config(cls, module_name: str) -> Optional[List[tuple]]:
        """Get configuration for module with validation"""
        return cls.MODULES.get(module_name) if module_name else None


class HypercallExtractor:
    """Main hypercall extraction engine with modern Python features"""
    
    def __init__(self, config: Config):
        self.config = config
        self.hardcoded = HardcodedHypercalls()
        self.parser = ParameterParser()
        self.resolver = UnknownHypercallResolver()
        self.known_hypercalls: Dict[Union[int, str], str] = {}
        self.unknown_hypercalls: Dict[int, HypercallEntry] = {}
        self.unknown_index = 0

    def extract_from_module(self, module_name: str) -> bool:
        """Extract hypercalls from specific module"""
        if not module_name:
            return False
            
        config = ModuleConfiguration.get_config(module_name)
        if not config:
            print(f"Unsupported module: {module_name}")
            return False

        total_processed = sum(self._process_function(func_name, param_idx) for func_name, param_idx in config)
        print(f"Processed {total_processed} hypercalls for {module_name}")
        return total_processed > 0

    def _process_function(self, func_name: str, param_index: int) -> int:
        """Process single function for hypercall extraction"""
        if not func_name or param_index < 0:
            return 0

        func_addr = idc.get_name_ea_simple(func_name)
        if func_addr == idc.BADADDR:
            return 0

        count = 0
        for xref in idautils.XrefsTo(func_addr, ida_xref.XREF_ALL):
            caller_name = self._get_function_name(xref.frm)
            if not caller_name:
                continue

            entry = self._extract_from_xref(xref, func_name, param_index, caller_name)
            if entry:
                self._add_hypercall(entry)
                count += 1

        return count

    def _get_function_name(self, address: int) -> Optional[str]:
        """Get function name with validation"""
        if address == idc.BADADDR:
            return None
        name = idc.get_func_name(address)
        return name if name and name != "WinHvpAllocatingHypercall" else None

    def _extract_from_xref(self, xref, func_name: str, param_idx: int, caller_name: str) -> Optional[HypercallEntry]:
        """Extract hypercall from cross-reference"""
        decompiled = DecompilerInterface.decompile_function(xref.frm)
        if not decompiled:
            return None

        param = DecompilerInterface.get_parameter_by_index(decompiled, func_name, param_idx)
        if not param:
            return None

        hv_id = self.parser.extract_hypercall_id(param, caller_name, self.hardcoded)
        return HypercallEntry(hv_id, caller_name, decompiled) if hv_id else None

    def _add_hypercall(self, entry: HypercallEntry) -> None:
        """Add hypercall with duplicate handling"""
        if isinstance(entry.id, str) and self.parser.contains_variables(entry.id):
            self.unknown_hypercalls[self.unknown_index] = entry
            self.unknown_index += 1
        else:
            # Handle numeric IDs with duplicate resolution
            resolved_id = entry.id
            if isinstance(resolved_id, int) and resolved_id in self.known_hypercalls:
                resolved_id += self.config.duplicate_prefix
                
            suffix = "_hardcoded" if self.hardcoded.find_by_name(entry.name) else ""
            self.known_hypercalls[resolved_id] = f"{entry.name}{suffix}"

    def resolve_unknowns(self) -> int:
        """Resolve unknown hypercalls and return count of resolved"""
        resolved_count = 0
        resolved_indices = []

        for idx, entry in self.unknown_hypercalls.items():
            concrete_value = self.resolver.resolve_from_body(str(entry.id), entry.name, entry.decompiled_code)
            if concrete_value is not None:
                self.known_hypercalls[concrete_value] = entry.name
                resolved_indices.append(idx)
                resolved_count += 1
                print(f"Resolved: {entry.id} -> {hex(concrete_value)} ({entry.name})")

        # Remove resolved entries
        for idx in resolved_indices:
            del self.unknown_hypercalls[idx]

        return resolved_count

    def save_results(self, idb_name: str, version: str) -> None:
        """Save results with automatic resolution"""
        if not idb_name:
            return

        FileOperations.ensure_directories(self.config.output_dir, self.config.unknown_dir)
        
        resolved_count = self.resolve_unknowns()
        
        # Save known hypercalls
        if self.known_hypercalls:
            main_file = self.config.output_dir / f"{idb_name}_{version}.json"
            sorted_data = self._create_sorted_output(self.known_hypercalls)
            FileOperations.save_json(main_file, sorted_data)

        # Save unknown hypercalls
        if self.unknown_hypercalls:
            unknown_file = self.config.unknown_dir / f"unknown_{idb_name}_{version}.json"
            unknown_data = {f"param_{idx}": {"parameter": str(entry.id), "function": entry.name, "function_body": entry.decompiled_code} 
                          for idx, entry in self.unknown_hypercalls.items()}
            FileOperations.save_json(unknown_file, unknown_data)

        self._print_summary(resolved_count)

    def _create_sorted_output(self, data: Dict[Union[int, str], str]) -> Dict[str, str]:
        """Create sorted output for JSON"""
        def sort_key(item):
            key = item[0]
            if isinstance(key, int):
                return (0, key)
            elif isinstance(key, str) and key.startswith('0x'):
                try:
                    return (0, int(key, 16))
                except ValueError:
                    return (1, key)
            else:
                return (1, key)

        sorted_items = sorted(data.items(), key=sort_key)
        return {(hex(k) if isinstance(k, int) else str(k)): v for k, v in sorted_items}

    def _print_summary(self, resolved_count: int) -> None:
        """Print extraction summary"""
        print(f"\nExtraction Summary:")
        print(f"Known hypercalls: {len(self.known_hypercalls)}")
        print(f"Unknown hypercalls: {len(self.unknown_hypercalls)}")
        if resolved_count > 0:
            print(f"Auto-resolved: {resolved_count}")


def main() -> None:
    """Main extraction function with modern error handling"""
    # Wait for auto-analysis if needed
    if len(idc.ARGV) > 0:
        ida_auto.auto_wait()

    # Initialize with modern configuration
    config = Config()
    extractor = HypercallExtractor(config)
    
    # Get module information
    idb_name = FileOperations.get_idb_name()
    version = FileOperations.get_file_version()
    
    if not idb_name:
        print("Error: Could not determine IDB name")
        return

    print(f"Processing: {idb_name} (v{version})")
    
    # Extract hypercalls
    if extractor.extract_from_module(idb_name):
        extractor.save_results(idb_name, version)
        print(f"Analysis complete for {idb_name}")
    else:
        print(f"No hypercalls extracted for {idb_name}")

    # Exit if running with arguments
    if len(idc.ARGV) > 0:
        idc.qexit(0)


if __name__ == "__main__":
    main()