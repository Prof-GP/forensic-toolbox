"""
Complete Standalone Windows Prefetch File Parser
Supports Windows XP through Windows 11 prefetch formats

Windows Prefetch File Structure:
- Header (84 bytes for v23, 88 bytes for v26, 92+ for v30)
- File Information Section
- Metrics Array
- Trace Chains Array
- Filename Strings
- Volumes Information
- Directory Strings
"""

import struct
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, BinaryIO, Tuple
import os


class ToolboxPrefetch:
    """
    Complete Windows Prefetch File Parser

    Prefetch files (.pf) are created by Windows to optimize application startup.
    They contain forensically valuable information about program execution.
    """

    # Prefetch format versions
    VERSION_WIN_XP = 17
    VERSION_WIN_VISTA_7 = 23
    VERSION_WIN_8 = 26
    VERSION_WIN_10 = 30

    def __init__(self, filepath: str):
        """Initialize parser with prefetch file path"""
        self.filepath = Path(filepath)
        self._file_handle: Optional[BinaryIO] = None
        self._decompressed_data: Optional[bytes] = None

        # Parsed data
        self.version: Optional[int] = None
        self.signature: Optional[int] = None
        self.executable_name: str = ""
        self.prefetch_hash: str = ""
        self.file_size: int = 0

        # File metrics
        self.run_count: int = 0
        self.last_run_times: List[datetime] = []

        # Sections offsets and sizes
        self.file_metrics_offset: int = 0
        self.file_metrics_count: int = 0
        self.trace_chains_offset: int = 0
        self.trace_chains_count: int = 0
        self.filename_strings_offset: int = 0
        self.filename_strings_size: int = 0
        self.volumes_info_offset: int = 0
        self.volumes_count: int = 0

        # Parsed content
        self.filename_strings: List[str] = []
        self.volumes: List[Dict] = []
        self.directory_strings: List[str] = []
        self.trace_chains: List[Dict] = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self):
        """Clean up resources"""
        if self._file_handle:
            self._file_handle.close()

    def debug_info(self):
        """Print debug information about the prefetch file structure"""
        print("\n=== DEBUG INFORMATION ===")
        print(f"File: {self.filepath}")
        print(f"File size: {len(self._decompressed_data)} bytes")
        print(f"Version: {self.version}")
        print(f"Signature: {self.signature:08X}")
        print(f"Executable: {self.executable_name}")
        print(f"Hash: {self.prefetch_hash}")

        print("\n--- Section Offsets ---")
        print(f"File metrics offset: {self.file_metrics_offset} (count: {self.file_metrics_count})")
        print(f"Trace chains offset: {self.trace_chains_offset} (count: {self.trace_chains_count})")
        print(f"Filename strings offset: {self.filename_strings_offset} (size: {self.filename_strings_size})")
        print(f"Volumes info offset: {self.volumes_info_offset} (count: {self.volumes_count})")

        print("\n--- Parsed Data ---")
        print(f"Run count: {self.run_count}")
        print(f"Last run times: {len(self.last_run_times)}")
        for i, ts in enumerate(self.last_run_times, 1):
            if ts:
                print(f"  {i}. {ts.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Filename strings: {len(self.filename_strings)}")
        print(f"Volumes: {len(self.volumes)}")
        print(f"Directory strings: {len(self.directory_strings)}")
        print(f"Trace chains: {len(self.trace_chains)}")

        # Show raw bytes around timestamp offset
        if self.version == 23:
            ts_offset = 84 + 44
            print(f"\n--- Raw timestamp bytes (offset {ts_offset}) ---")
            if len(self._decompressed_data) >= ts_offset + 8:
                ts_bytes = self._decompressed_data[ts_offset:ts_offset+8]
                ts_value = struct.unpack('<Q', ts_bytes)[0]
                print(f"Bytes: {ts_bytes.hex()}")
                print(f"Value: {ts_value}")
                if ts_value > 0:
                    print(f"Converted: {self._convert_filetime(ts_value)}")
        else:  # v26/v30
            ts_offset = 84 + 44
            print(f"\n--- Raw timestamp bytes (offset {ts_offset}, 8 timestamps) ---")
            for i in range(8):
                offset = ts_offset + (i * 8)
                if len(self._decompressed_data) >= offset + 8:
                    ts_bytes = self._decompressed_data[offset:offset+8]
                    ts_value = struct.unpack('<Q', ts_bytes)[0]
                    if ts_value > 0:
                        print(f"Timestamp {i+1}: {ts_value} -> {self._convert_filetime(ts_value)}")

        # Show raw bytes around run count offset
        if self.version == 23:
            offset = 84 + 68
        else:  # v26/v30
            offset = 84 + 124

        print(f"\n--- Raw bytes around run count (offset {offset}) ---")
        if len(self._decompressed_data) > offset + 4:
            print(f"Bytes {offset-4} to {offset+8}:")
            for i in range(offset-4, offset+8):
                if i >= 0 and i < len(self._decompressed_data):
                    print(f"  [{i:4d}] 0x{self._decompressed_data[i]:02X} ({self._decompressed_data[i]:3d})")

        print("========================\n")

    def parse(self) -> bool:
        """
        Main parsing method

        Returns:
            True if parsing succeeded, False otherwise
        """
        try:
            # Read and decompress if needed
            with open(self.filepath, 'rb') as f:
                data = f.read()

            # Check for MAM compression (Windows 10+)
            if data[:3] == b'MAM':
                print("Detected compressed prefetch file (Windows 10+)")
                try:
                    data = self._decompress_win10(data)
                except Exception as e:
                    print(f"Decompression failed: {e}")
                    return False

            # Parse from decompressed data
            self._decompressed_data = data

            # Parse header
            if not self._parse_header():
                return False

            print(f"Prefetch version: {self.version}")
            print(f"Executable: {self.executable_name}")

            # Parse based on version
            if self.version == self.VERSION_WIN_XP:
                return self._parse_v17()
            elif self.version == self.VERSION_WIN_VISTA_7:
                return self._parse_v23()
            elif self.version == self.VERSION_WIN_8:
                return self._parse_v26()
            elif self.version == self.VERSION_WIN_10:
                return self._parse_v30()
            else:
                print(f"Unsupported version: {self.version}")
                return False

        except Exception as e:
            print(f"Error parsing prefetch: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _decompress_win10(self, data: bytes) -> bytes:
        """
        Decompress Windows 10+ compressed prefetch files
        Uses MAM compression (XPRESS with Huffman)
        """
        # Try using windowsprefetch library if available
        try:
            from windowsprefetch.utils import DecompressWin10
            decompressor = DecompressWin10()
            return decompressor.decompress(self.filepath)
        except ImportError:
            pass

        # Try using pyxpress-huffman
        try:
            import pyxpress
            # Skip MAM header (8 bytes)
            compressed_data = data[8:]
            # Decompress
            decompressed = pyxpress.decompress(compressed_data)
            return decompressed
        except ImportError:
            print("Warning: No decompression library available")
            print("Install: pip install pyxpress")

        raise Exception("Cannot decompress - no decompression library available")

    def _parse_header(self) -> bool:
        """Parse prefetch file header"""
        if len(self._decompressed_data) < 84:
            print("File too small to be a valid prefetch file")
            return False

        # First 4 bytes: version
        self.version = struct.unpack('<I', self._decompressed_data[0:4])[0]

        # Signature (should be 'SCCA')
        signature_bytes = self._decompressed_data[4:8]
        self.signature = struct.unpack('<I', signature_bytes)[0]

        if signature_bytes != b'SCCA':
            print(f"Invalid signature: {signature_bytes}")
            return False

        # Unknown field (4 bytes)
        # Skip bytes 8-12

        # File size
        self.file_size = struct.unpack('<I', self._decompressed_data[12:16])[0]

        # Executable name (60 bytes, UTF-16 LE)
        name_bytes = self._decompressed_data[16:76]
        self.executable_name = name_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')

        # Prefetch hash (4 bytes)
        hash_value = struct.unpack('<I', self._decompressed_data[76:80])[0]
        self.prefetch_hash = f"{hash_value:08X}"

        # Flags (4 bytes) - varies by version
        # Skip bytes 80-84

        return True

    def _parse_file_info_v23(self, offset: int = 84):
        """Parse file information section for version 23 (Vista/7)"""
        data = self._decompressed_data

        # File metrics array offset and count
        self.file_metrics_offset = struct.unpack('<I', data[offset:offset+4])[0]
        self.file_metrics_count = struct.unpack('<I', data[offset+4:offset+8])[0]

        # Trace chains array offset and count
        self.trace_chains_offset = struct.unpack('<I', data[offset+8:offset+12])[0]
        self.trace_chains_count = struct.unpack('<I', data[offset+12:offset+16])[0]

        # Filename strings offset and size
        self.filename_strings_offset = struct.unpack('<I', data[offset+16:offset+20])[0]
        self.filename_strings_size = struct.unpack('<I', data[offset+20:offset+24])[0]

        # Volumes information offset and count
        self.volumes_info_offset = struct.unpack('<I', data[offset+24:offset+28])[0]
        self.volumes_count = struct.unpack('<I', data[offset+28:offset+32])[0]

        # Volumes information size (4 bytes)
        # Skip offset+32:offset+36

        # Unknown (8 bytes)
        # Skip offset+36:offset+44

        # Last run time (8 bytes, FILETIME) - offset 44
        filetime = struct.unpack('<Q', data[offset+44:offset+52])[0]
        if filetime > 0:
            self.last_run_times.append(self._convert_filetime(filetime))

        # Unknown (16 bytes)
        # Skip offset+52:offset+68

        # Run count (4 bytes) - offset 68
        self.run_count = struct.unpack('<I', data[offset+68:offset+72])[0]

        print(f"DEBUG v23: Run count at offset {offset+68}: {self.run_count}")

        # Unknown (4 bytes)
        # Skip offset+72:offset+76

    def _parse_file_info_v26(self, offset: int = 84):
        """Parse file information section for version 26 (Windows 8)"""
        data = self._decompressed_data

        # File metrics array offset and count
        self.file_metrics_offset = struct.unpack('<I', data[offset:offset+4])[0]
        self.file_metrics_count = struct.unpack('<I', data[offset+4:offset+8])[0]

        # Trace chains array offset and count
        self.trace_chains_offset = struct.unpack('<I', data[offset+8:offset+12])[0]
        self.trace_chains_count = struct.unpack('<I', data[offset+12:offset+16])[0]

        # Filename strings offset and size
        self.filename_strings_offset = struct.unpack('<I', data[offset+16:offset+20])[0]
        self.filename_strings_size = struct.unpack('<I', data[offset+20:offset+24])[0]

        # Volumes information offset and count
        self.volumes_info_offset = struct.unpack('<I', data[offset+24:offset+28])[0]
        self.volumes_count = struct.unpack('<I', data[offset+28:offset+32])[0]

        # Volumes information size (4 bytes)
        # Skip offset+32:offset+36

        # Unknown (8 bytes)
        # Skip offset+36:offset+44

        # Last run times (8 timestamps of 8 bytes each = 64 bytes) - offset 44-107
        for i in range(8):
            ts_offset = offset + 44 + (i * 8)
            filetime = struct.unpack('<Q', data[ts_offset:ts_offset+8])[0]
            if filetime > 0:
                self.last_run_times.append(self._convert_filetime(filetime))

        # Unknown (16 bytes)
        # Skip offset+108:offset+124

        # Run count (4 bytes) - offset 124
        self.run_count = struct.unpack('<I', data[offset+124:offset+128])[0]

        print(f"DEBUG v26/v30: Run count at offset {offset+124}: {self.run_count}")

        # Unknown (80 bytes)
        # Skip offset+128:offset+208

    def _parse_file_info_v30(self, offset: int = 84):
        """Parse file information section for version 30 (Windows 10)"""
        # Version 30 has same structure as v26 for file info
        self._parse_file_info_v26(offset)

    def _parse_v17(self) -> bool:
        """Parse Windows XP prefetch (version 17)"""
        print("Windows XP format parsing not fully implemented")
        # XP format is simpler, typically starts at offset 84
        self._parse_file_info_v23(84)
        self._parse_filename_strings()
        self._parse_volumes()
        return True

    def _parse_v23(self) -> bool:
        """Parse Windows Vista/7 prefetch (version 23)"""
        self._parse_file_info_v23(84)
        self._parse_filename_strings()
        self._parse_volumes()
        self._parse_trace_chains_v23()
        return True

    def _parse_v26(self) -> bool:
        """Parse Windows 8 prefetch (version 26)"""
        self._parse_file_info_v26(84)
        self._parse_filename_strings()
        self._parse_volumes()
        self._parse_trace_chains_v26()
        return True

    def _parse_v30(self) -> bool:
        """Parse Windows 10/11 prefetch (version 30)"""
        self._parse_file_info_v30(84)
        self._parse_filename_strings()
        self._parse_volumes()
        self._parse_trace_chains_v26()  # Same as v26
        return True

    def _parse_filename_strings(self):
        """Parse the filename strings section"""
        if not self.filename_strings_offset or not self.filename_strings_size:
            return

        offset = self.filename_strings_offset
        end = offset + self.filename_strings_size
        data = self._decompressed_data

        self.filename_strings = []

        # Filename strings are null-terminated UTF-16 LE strings
        while offset < end - 2:
            # Find next null terminator
            null_pos = offset
            while null_pos < end - 1:
                if data[null_pos:null_pos+2] == b'\x00\x00':
                    break
                null_pos += 2

            if null_pos >= end:
                break

            # Extract string
            string_bytes = data[offset:null_pos]
            if len(string_bytes) > 0:
                try:
                    filename = string_bytes.decode('utf-16-le', errors='ignore')
                    if filename.strip():
                        self.filename_strings.append(filename)
                except:
                    pass

            offset = null_pos + 2

    def _parse_volumes(self):
        """Parse volumes information"""
        if not self.volumes_info_offset or not self.volumes_count:
            return

        self.volumes = []
        offset = self.volumes_info_offset
        data = self._decompressed_data

        # Each volume entry has variable size
        for vol_idx in range(self.volumes_count):
            volume = {}

            # Volume device path offset (4 bytes)
            vol_path_offset = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            # Volume device path length (4 bytes, in characters)
            vol_path_length = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            # Volume creation time (8 bytes, FILETIME)
            vol_creation_time = struct.unpack('<Q', data[offset:offset+8])[0]
            volume['creation_time'] = self._convert_filetime(vol_creation_time)
            offset += 8

            # Volume serial number (4 bytes)
            vol_serial = struct.unpack('<I', data[offset:offset+4])[0]
            volume['serial_number'] = f"{vol_serial:08X}"
            offset += 4

            # File references offset (4 bytes)
            file_refs_offset = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            # File references count (4 bytes)
            file_refs_count = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            # Directory strings offset (4 bytes)
            dir_strings_offset = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            # Directory strings count (4 bytes)
            dir_strings_count = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4

            # Unknown (4 bytes)
            offset += 4

            # Read volume path
            if vol_path_offset > 0 and vol_path_length > 0:
                path_start = self.volumes_info_offset + vol_path_offset
                path_bytes = data[path_start:path_start + (vol_path_length * 2)]
                volume['path'] = path_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
            else:
                volume['path'] = ""

            # Read directory strings for this volume
            volume['directories'] = []
            if dir_strings_count > 0:
                dir_offset = self.volumes_info_offset + dir_strings_offset
                for _ in range(dir_strings_count):
                    # Read string length (2 bytes)
                    if dir_offset + 2 > len(data):
                        break
                    str_len = struct.unpack('<H', data[dir_offset:dir_offset+2])[0]
                    dir_offset += 2

                    # Read string
                    if dir_offset + (str_len * 2) > len(data):
                        break
                    str_bytes = data[dir_offset:dir_offset + (str_len * 2)]
                    dir_offset += str_len * 2

                    try:
                        dir_str = str_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
                        if dir_str:
                            volume['directories'].append(dir_str)
                            self.directory_strings.append(dir_str)
                    except:
                        pass

            self.volumes.append(volume)

    def _parse_trace_chains_v23(self):
        """Parse trace chains for version 23"""
        if not self.trace_chains_offset or not self.trace_chains_count:
            return

        offset = self.trace_chains_offset
        data = self._decompressed_data

        self.trace_chains = []

        # Each entry is 8 bytes in v23
        for i in range(self.trace_chains_count):
            if offset + 8 > len(data):
                break

            next_array_entry_index = struct.unpack('<I', data[offset:offset+4])[0]
            total_block_load_count = struct.unpack('<I', data[offset+4:offset+8])[0]

            self.trace_chains.append({
                'index': i,
                'next_entry': next_array_entry_index,
                'block_load_count': total_block_load_count
            })

            offset += 8

    def _parse_trace_chains_v26(self):
        """Parse trace chains for version 26/30"""
        if not self.trace_chains_offset or not self.trace_chains_count:
            return

        offset = self.trace_chains_offset
        data = self._decompressed_data

        self.trace_chains = []

        # Each entry is 12 bytes in v26/30
        for i in range(self.trace_chains_count):
            if offset + 12 > len(data):
                break

            next_array_entry_index = struct.unpack('<I', data[offset:offset+4])[0]
            total_block_load_count = struct.unpack('<I', data[offset+4:offset+8])[0]
            unknown = struct.unpack('<I', data[offset+8:offset+12])[0]

            self.trace_chains.append({
                'index': i,
                'next_entry': next_array_entry_index,
                'block_load_count': total_block_load_count,
                'sample_duration': unknown
            })

            offset += 12

    @staticmethod
    def _convert_filetime(filetime: int) -> datetime:
        """Convert Windows FILETIME to datetime"""
        if filetime == 0:
            return None
        try:
            # FILETIME is 100-nanosecond intervals since 1601-01-01
            return datetime(1601, 1, 1) + timedelta(microseconds=filetime / 10)
        except:
            return None

    def print_summary(self, show_all: bool = True, max_items: int = None):
        """
        Print a comprehensive summary of the parsed prefetch data

        Args:
            show_all: If True, print all items. If False, limit output.
            max_items: Maximum items to show per section (None = show all)
        """
        print("\n" + "="*70)
        print(f"PREFETCH ANALYSIS: {self.filepath.name}")
        print("="*70)

        print(f"\nExecutable Name: {self.executable_name}")
        print(f"Prefetch Hash: {self.prefetch_hash}")
        print(f"Version: {self.version}")
        print(f"Run Count: {self.run_count}")

        # Last execution times
        if self.last_run_times:
            print(f"\nLast Execution Times ({len(self.last_run_times)}):")
            for i, ts in enumerate(self.last_run_times, 1):
                if ts:
                    print(f"  {i}. {ts.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}")  # Include milliseconds
                else:
                    print(f"  {i}. (Invalid timestamp)")
        else:
            print("\nLast Execution Times: None found")

        # Volume information
        if self.volumes:
            print(f"\nVolumes ({len(self.volumes)}):")
            for i, vol in enumerate(self.volumes, 1):
                print(f"\n  Volume {i}:")
                print(f"    Path: {vol.get('path', 'N/A')}")
                print(f"    Serial: {vol.get('serial_number', 'N/A')}")
                if vol.get('creation_time'):
                    print(f"    Created: {vol['creation_time'].strftime('%Y-%m-%d %H:%M:%S')}")
                if vol.get('directories'):
                    print(f"    Directories: {len(vol['directories'])}")

        # Referenced files (most important - show ALL)
        if self.filename_strings:
            print(f"\n{'='*70}")
            print(f"REFERENCED FILES ({len(self.filename_strings)} total)")
            print(f"{'='*70}")

            # Categorize files
            dlls = []
            exes = []
            sys_files = []
            others = []

            for filename in self.filename_strings:
                filename_upper = filename.upper()
                if filename_upper.endswith('.DLL'):
                    dlls.append(filename)
                elif filename_upper.endswith('.EXE'):
                    exes.append(filename)
                elif filename_upper.endswith(('.SYS', '.DRV')):
                    sys_files.append(filename)
                else:
                    others.append(filename)

            # Print DLLs
            if dlls:
                print(f"\nDLL Files ({len(dlls)}):")
                limit = None if show_all or max_items is None else max_items
                for i, dll in enumerate(dlls[:limit] if limit else dlls, 1):
                    print(f"  {i:4d}. {dll}")
                if limit and len(dlls) > limit:
                    print(f"  ... and {len(dlls) - limit} more DLLs")

            # Print EXEs
            if exes:
                print(f"\nExecutable Files ({len(exes)}):")
                limit = None if show_all or max_items is None else max_items
                for i, exe in enumerate(exes[:limit] if limit else exes, 1):
                    print(f"  {i:4d}. {exe}")
                if limit and len(exes) > limit:
                    print(f"  ... and {len(exes) - limit} more executables")

            # Print system files
            if sys_files:
                print(f"\nSystem/Driver Files ({len(sys_files)}):")
                limit = None if show_all or max_items is None else max_items
                for i, sys_file in enumerate(sys_files[:limit] if limit else sys_files, 1):
                    print(f"  {i:4d}. {sys_file}")
                if limit and len(sys_files) > limit:
                    print(f"  ... and {len(sys_files) - limit} more system files")

            # Print other files
            if others:
                print(f"\nOther Files ({len(others)}):")
                limit = None if show_all or max_items is None else max_items
                for i, other in enumerate(others[:limit] if limit else others, 1):
                    print(f"  {i:4d}. {other}")
                if limit and len(others) > limit:
                    print(f"  ... and {len(others) - limit} more files")

        # Referenced directories (show ALL)
        if self.directory_strings:
            print(f"\n{'='*70}")
            print(f"REFERENCED DIRECTORIES ({len(self.directory_strings)} total)")
            print(f"{'='*70}\n")

            limit = None if show_all or max_items is None else max_items
            for i, dir_str in enumerate(self.directory_strings[:limit] if limit else self.directory_strings, 1):
                print(f"  {i:4d}. {dir_str}")
            if limit and len(self.directory_strings) > limit:
                print(f"  ... and {len(self.directory_strings) - limit} more directories")

        # Trace chains summary
        if self.trace_chains:
            total_blocks = sum(tc['block_load_count'] for tc in self.trace_chains)
            print(f"\n{'='*70}")
            print(f"TRACE CHAINS INFORMATION")
            print(f"{'='*70}")
            print(f"Total Trace Chain Entries: {len(self.trace_chains)}")
            print(f"Total Block Load Count: {total_blocks}")

        print("\n" + "="*70)

    def to_dict(self) -> Dict:
        """Export all parsed data as dictionary"""
        return {
            'filepath': str(self.filepath),
            'executable_name': self.executable_name,
            'prefetch_hash': self.prefetch_hash,
            'version': self.version,
            'run_count': self.run_count,
            'last_run_times': [ts.isoformat() if ts else None for ts in self.last_run_times],
            'volumes': self.volumes,
            'filename_strings': self.filename_strings,
            'directory_strings': self.directory_strings,
            'trace_chains_count': len(self.trace_chains),
            'total_block_loads': sum(tc['block_load_count'] for tc in self.trace_chains),
        }


def main():
    """Command line interface"""
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python prefetch_parser.py <prefetch_file.pf> [options]")
        print("\nOptions:")
        print("  --json <file>   Export to JSON file")
        print("  --limit <n>     Limit output to first n items per section")
        print("  --summary       Show summary only (limited output)")
        print("  --debug         Show debug information about file structure")
        print("\nExamples:")
        print("  python prefetch_parser.py CALC.EXE-12345.pf")
        print("  python prefetch_parser.py CALC.EXE-12345.pf --json output.json")
        print("  python prefetch_parser.py CALC.EXE-12345.pf --limit 50")
        print("  python prefetch_parser.py CALC.EXE-12345.pf --debug")
        sys.exit(1)

    filepath = sys.argv[1]

    if not os.path.exists(filepath):
        print(f"Error: File not found: {filepath}")
        sys.exit(1)

    # Parse options
    show_all = True  # Default to showing everything
    max_items = None

    if '--summary' in sys.argv:
        show_all = False
        max_items = 20  # Limit to 20 items per section in summary mode

    if '--limit' in sys.argv:
        try:
            limit_idx = sys.argv.index('--limit')
            if limit_idx + 1 < len(sys.argv):
                max_items = int(sys.argv[limit_idx + 1])
                show_all = False
        except (ValueError, IndexError):
            print("Error: --limit requires a number")
            sys.exit(1)

    # Parse the prefetch file
    with ToolboxPrefetch(filepath) as parser:
        if parser.parse():
            # Show debug info if requested
            if '--debug' in sys.argv:
                parser.debug_info()

            # Print summary with all details by default
            parser.print_summary(show_all=show_all, max_items=max_items)

            # Export to JSON if requested
            if '--json' in sys.argv:
                try:
                    json_idx = sys.argv.index('--json')
                    if json_idx + 1 < len(sys.argv):
                        output_file = sys.argv[json_idx + 1]
                        with open(output_file, 'w') as f:
                            json.dump(parser.to_dict(), f, indent=2, default=str)
                        print(f"\nExported to: {output_file}")
                except (ValueError, IndexError):
                    print("Error: --json requires output filename")
        else:
            print("Failed to parse prefetch file")
            sys.exit(1)


if __name__ == "__main__":
    main()