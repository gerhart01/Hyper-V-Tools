# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
# Modified version for Hyper-V memory access plugin integration
#

import logging
import os
import sys
import threading
from typing import Any, Dict, List, Optional, Union

from hvlib import *
from volatility3.framework import exceptions, interfaces, constants
from volatility3.framework.configuration import requirements

g_lkd_handle = 0
g_vm_handle = 0

vollog = logging.getLogger(__name__)

# --- Diagnostic read logger for Volatility scan analysis ---
_HVLOG_PATH = os.path.join(os.environ.get("TEMP", "."), "hyperv_reads.log")
_hvlog_file = None
_hvlog_lock = threading.Lock()


def _hvlog_init():
    global _hvlog_file
    if _hvlog_file is None:
        try:
            _hvlog_file = open(_HVLOG_PATH, "w")
            _hvlog_file.write("action,offset_hex,length_hex,length_dec,returned_hex,returned_dec,status\n")
            _hvlog_file.flush()
            print(f"[hyperv] Read log: {_HVLOG_PATH}", file=sys.stderr)
        except Exception:
            _hvlog_file = False  # Disable on error


def _hvlog(offset: int, length: int, returned: int, status: str):
    global _hvlog_file
    with _hvlog_lock:
        if _hvlog_file is None:
            _hvlog_init()
        if _hvlog_file and _hvlog_file is not False:
            _hvlog_file.write(
                f"read,0x{offset:X},0x{length:X},{length},0x{returned:X},{returned},{status}\n"
            )
            _hvlog_file.flush()


class BufferDataLayer(interfaces.layers.DataLayerInterface):
    """A DataLayer class backed by a buffer in memory, designed for testing and
    swift data access."""

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 buffer: bytes,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context = context, config_path = config_path, name = name, metadata = metadata)
        self._buffer = buffer

    @property
    def maximum_address(self) -> int:
        """Returns the largest available address in the space."""
        return len(self._buffer) - 1

    @property
    def minimum_address(self) -> int:
        """Returns the smallest available address in the space."""
        return 0

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the offset is valid or not."""
        return bool(self.minimum_address <= offset <= self.maximum_address
                    and self.minimum_address <= offset + length - 1 <= self.maximum_address)

    def read(self, address: int, length: int, pad: bool = False) -> bytes:
        """Reads the data from the buffer."""
        if not self.is_valid(address, length):
            invalid_address = address
            if self.minimum_address < address <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(self.name, invalid_address,
                                                     "Offset outside of the buffer boundaries")
        return self._buffer[address:address + length]

    def write(self, address: int, data: bytes):
        """Writes the data from to the buffer."""
        self._buffer = self._buffer[:address] + data + self._buffer[address + len(data):]

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # No real requirements (only the buffer).  Need to figure out if there's a better way of representing this
        return [
            requirements.BytesRequirement(name = 'buffer',
                                          description = "The direct bytes to interact with",
                                          optional = False)
        ]


class DummyLock:

    def __enter__(self) -> None:
        pass

    def __exit__(self, type, value, traceback) -> None:
        pass


class FileLayer(interfaces.layers.DataLayerInterface):
    """a DataLayer backed by Hyper-V live VM memory via hvlib.dll."""

    def __init__(self,
                 context: interfaces.context.ContextInterface,
                 config_path: str,
                 name: str,
                 metadata: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(context = context, config_path = config_path, name = name, metadata = metadata)

        global g_lkd_handle
        global g_vm_handle

        if g_lkd_handle == 0:

            dll_path = os.path.join(sys.exec_prefix, "Lib", "site-packages", "hvlib", "hvlib.dll")
            lkd_handle = hvlib(dll_path)
            g_lkd_handle = lkd_handle

            vm_ops = lkd_handle.vm_ops
            vm_ops.LogLevel = 1

            b_result = lkd_handle.EnumPartitions(vm_ops)

            if b_result == False:
                print("EnumPartitions false")
                return None

            print("Select virtual machine ID:")
            vm_id = int(input('').split(" ")[0])
            #vm_id = 0

            vm_handle = lkd_handle.SelectPartition(vm_id)
            g_vm_handle = vm_handle
            self._lkd_handle = lkd_handle
            self._vm_handle = vm_handle
        else:
            self._lkd_handle = g_lkd_handle
            self._vm_handle = g_vm_handle
            lkd_handle = g_lkd_handle
            vm_handle = g_vm_handle

        self._location = self.config["location"]
        # NOTE: Do NOT open the file via ResourceAccessor/urllib here.
        # After hvlib.dll loads hvmm.sys driver, urllib's importlib._path_stat
        # triggers an access violation (segfault).  The hyperv layer reads
        # live VM memory through hvlib, so the file handle is unnecessary.
        self._maximum_address: int = lkd_handle.GetData(vm_handle, HvmmInformationClass.InfoMmMaximumPhysicalPage) * 0x1000
        # Construct the lock now (shared if made before threading) in case we ever need it
        self._lock: Union[DummyLock, threading.Lock] = DummyLock()
        if constants.PARALLELISM == constants.Parallelism.Threading:
            self._lock = threading.Lock()

    @property
    def location(self) -> str:
        """Returns the location on which this Layer abstracts."""
        return self._location

    @property
    def maximum_address(self) -> int:
        """Returns the largest available address in the space."""
        return self._maximum_address

    @property
    def minimum_address(self) -> int:
        """Returns the smallest available address in the space."""
        return 0

    def is_valid(self, offset: int, length: int = 1) -> bool:
        """Returns whether the offset is valid or not."""
        if length <= 0:
            raise ValueError("Length must be positive")

        return bool(self.minimum_address <= offset <= (self.maximum_address + 0x2000) # 0x2000 size of DUMP_HEADER64
                    and self.minimum_address <= offset + length - 1 <= self.maximum_address + 0x2000)

    def read(self, offset: int, length: int, pad: bool = False) -> bytes:
        """Reads from the file at offset for length."""

        if not self.is_valid(offset, length):
            _hvlog(offset, length, 0, "INVALID_RANGE")
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(self.name, invalid_address,
                                                     "Offset outside of the buffer boundaries")

        with self._lock:
            try:
                data = self._lkd_handle.ReadPhysicalMemoryBlock(self._vm_handle, offset, length)
            except Exception as e:
                _hvlog(offset, length, 0, f"EXCEPTION:{type(e).__name__}:{e}")
                raise

        if data == 0:
            # ReadPhysicalMemoryBlock returns 0 on failure
            _hvlog(offset, length, 0, "SDK_READ_FAILED")
            if pad:
                return b"\x00" * length
            raise exceptions.InvalidAddressException(
                self.name, offset, "ReadPhysicalMemoryBlock returned 0")

        returned = len(data) if data else 0
        if returned < length:
            _hvlog(offset, length, returned, f"SHORT_READ(pad={pad})")
            if pad:
                data += (b"\x00" * (length - returned))
            else:
                raise exceptions.InvalidAddressException(
                    self.name, offset + returned, "Could not read sufficient bytes from the " + self.name + " file")
        else:
            _hvlog(offset, length, returned, "OK")
        return data

    def write(self, offset: int, data: bytes) -> None:
        """Writes to the VM physical memory via hvlib."""
        if not self.is_valid(offset, len(data)):
            invalid_address = offset
            if self.minimum_address < offset <= self.maximum_address:
                invalid_address = self.maximum_address + 1
            raise exceptions.InvalidAddressException(self.name, invalid_address,
                                                     "Data segment outside of the " + self.name + " file boundaries")
        with self._lock:
            self._lkd_handle.WritePhysicalMemoryBlock(self._vm_handle, offset, data)

    def __getstate__(self) -> Dict[str, Any]:
        """Prepare state for pickling (multi-processing support)."""
        return self.__dict__

    def destroy(self) -> None:
        """Closes the file handle."""
        global g_lkd_handle
        self._lkd_handle.cleanup()
        g_lkd_handle = 0
        g_vm_handle = 0

    def __exit__(self, type, value, traceback) -> None:
        self.destroy()

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [requirements.StringRequirement(name = 'location', optional = False)]
