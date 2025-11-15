#!/usr/bin/env python3
"""
Forensic Toolbox - Windows Forensic Artifacts Parser
Automatically detects and parses Windows forensic artifacts including:
- Registry hives (SOFTWARE, SYSTEM, SAM, NTUSER, SECURITY)
- Prefetch files (.pf)
- Windows shortcuts (.lnk)
"""

import argparse
import sys
from pathlib import Path
from Toolbox.toolbox_lnk import ToolboxLnk
from Toolbox.toolbox_registry import ToolboxRegistry
from Toolbox.toolbox_prefetch import ToolboxPrefetch
from Toolbox.toolbox_evtx import ToolboxEvtx


class ForensicToolbox:
    """Main forensic toolbox class for automatic artifact detection and parsing"""
    
    REGISTRY_HIVES = {
        'SOFTWARE': 'SOFTWARE',
        'SYSTEM': 'SYSTEM',
        'SAM': 'SAM',
        'NTUSER.DAT': 'NTUSER',
        'NTUSER': 'NTUSER',
        'SECURITY': 'SECURITY',
        'USRCLASS.DAT': 'USRCLASS',
        'USRCLASS': 'USRCLASS'
    }
    
    def __init__(self):
        self.verbose = False
    
    def detect_file_type(self, filepath):
        """
        Automatically detect the type of forensic artifact
        
        Args:
            filepath: Path to the file
            
        Returns:
            tuple: (file_type, additional_info)
        """
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        # Check if it's a directory
        if path.is_dir():
            # Check if directory contains EVTX files
            if list(path.glob('*.evtx')):
                return ('evtx_dir', None)
            return ('unknown', None)
        
        # Check file extension
        ext = path.suffix.lower()
        
        if ext == '.lnk':
            return ('lnk', None)
        
        if ext == '.pf':
            return ('prefetch', None)
        
        if ext == '.evtx':
            return ('evtx', None)
        
        # Check filename for registry hives (case-insensitive)
        name_upper = path.name.upper()
        for hive_name, hive_type in self.REGISTRY_HIVES.items():
            if hive_name in name_upper:
                return ('registry', hive_type)
        
        # Try to detect by file signature
        try:
            with open(filepath, 'rb') as f:
                signature = f.read(8)
                
                # LNK file signature
                if signature[:4] == b'\x4C\x00\x00\x00':
                    return ('lnk', None)
                
                # Registry hive signature (regf)
                if signature[:4] == b'regf':
                    # Try to guess hive type from path or name
                    hive_type = self._guess_registry_type(path)
                    return ('registry', hive_type)
                
                # Prefetch file signature
                if signature[4:8] == b'SCCA':
                    return ('prefetch', None)
                
                # Compressed prefetch (Windows 10+)
                if signature[:3] == b'MAM':
                    return ('prefetch', None)
        
        except Exception as e:
            if self.verbose:
                print(f"[!] Error reading file signature: {e}")
        
        return ('unknown', None)
    
    def _guess_registry_type(self, path):
        """
        Guess registry hive type from filename or path
        
        Args:
            path: Path object
            
        Returns:
            str: Registry hive type or None
        """
        name_upper = path.name.upper()
        path_str = str(path).upper()
        
        # Check filename
        for hive_name, hive_type in self.REGISTRY_HIVES.items():
            if hive_name in name_upper:
                return hive_type
        
        # Check path components
        if 'SYSTEM32\\CONFIG' in path_str:
            if 'SOFTWARE' in name_upper:
                return 'SOFTWARE'
            elif 'SYSTEM' in name_upper:
                return 'SYSTEM'
            elif 'SAM' in name_upper:
                return 'SAM'
            elif 'SECURITY' in name_upper:
                return 'SECURITY'
        
        # If in user profile path
        if any(x in path_str for x in ['USERS\\', 'DOCUMENTS AND SETTINGS\\']):
            if 'NTUSER.DAT' in name_upper:
                return 'NTUSER'
            elif 'USRCLASS.DAT' in name_upper:
                return 'USRCLASS'
        
        return None
    
    def process_file(self, filepath, args):
        """
        Process a forensic artifact file
        
        Args:
            filepath: Path to the file
            registry_type: Override registry type detection
            output: Output file path (optional)
        """
        output = getattr(args, 'output', None)
        registry_type = getattr(args, 'type', None)

        file_type, detected_info = self.detect_file_type(filepath)
        
        print(f"\n{'='*70}")
        print(f"FORENSIC TOOLBOX - Analyzing: {Path(filepath).name}")
        print(f"{'='*70}")
        
        if file_type == 'unknown':
            print(f"[!] Unknown file type: {filepath}")
            print("[!] Supported types: .lnk, .pf, registry hives")
            return False
        
        print(f"[*] Detected file type: {file_type.upper()}")
        
        try:
            if file_type == 'lnk':
                self._process_lnk(filepath, args)
            
            elif file_type == 'prefetch':
                self._process_prefetch(filepath, args)
            
            elif file_type == 'registry':
                # Use provided registry type or detected type
                hive_type = registry_type or detected_info
                if not hive_type:
                    print("[!] Cannot determine registry hive type.")
                    print("[*] Please specify with --type option")
                    print("[*] Valid types: SOFTWARE, SYSTEM, SAM, NTUSER, SECURITY, USRCLASS")
                    return False
                
                self._process_registry(filepath, hive_type, args)
            
            elif file_type == 'evtx':
                self._process_evtx(filepath, args, is_directory=False)
        
            elif file_type == 'evtx_dir':
                self._process_evtx(filepath, args, is_directory=True)
            
            print(f"\n{'='*70}")
            print("[+] Analysis complete!")
            print(f"{'='*70}\n")
            return True
            
        except Exception as e:
            print(f"\n[!] Error processing file: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()
            return False
    
    def _process_lnk(self, filepath, args):
        """Process Windows shortcut (.lnk) file"""
        output = getattr(args, 'output', None)

        print(f"[*] Parsing LNK file...")
        lnk = ToolboxLnk(filepath)
        
        if output:
            print(f"[*] Output functionality not yet implemented for LNK files")
    
    def _process_prefetch(self, filepath, args):
        """Process Windows prefetch (.pf) file"""
        print(f"[*] Parsing Prefetch file...")
        output = getattr(args, 'output', None)

        with ToolboxPrefetch(filepath) as parser:
            if parser.parse():
                parser.print_summary(show_all=True)
                
                if output:
                    if output.endswith('.json'):
                        import json
                        with open(output, 'w') as f:
                            json.dump(parser.to_dict(), f, indent=2, default=str)
                        print(f"[+] Exported to: {output}")
                    else:
                        print(f"[!] Unsupported output format for prefetch. Use .json extension.")
            else:
                print("[!] Failed to parse prefetch file")
    
    def _process_registry(self, filepath, hive_type, args):
        """Process Windows registry hive"""
        print(f"[*] Registry hive type: {hive_type}")
        print(f"[*] Extracting forensic artifacts...")
        
        output = getattr(args, 'output', None)
        
        reg = ToolboxRegistry(filepath, hive_type)
        results = reg.valuable_keys()
        
        if results:
            reg.print_results(results)
            
            if output:
                if output.endswith('.json'):
                    reg.export_to_json(output, results)
                elif output.endswith('.csv'):
                    reg.export_to_csv(output, results)
                else:
                    print(f"[!] Unsupported output format. Use .json or .csv extension.")
        else:
            print(f"[!] No forensic artifacts found in {hive_type} hive")

    def _process_evtx(self, filepath, args, is_directory=False):
        """Process Windows Event Log file or directory"""
        try:
            from Toolbox.toolbox_evtx import ToolboxEvtx
            
            # Extract EVTX-specific arguments from args
            start_date = getattr(args, 'evtx_start', None)
            end_date = getattr(args, 'evtx_end', None)
            event_ids = getattr(args, 'evtx_events', None)
            all_events = getattr(args, 'evtx_all', False)
            powershell = getattr(args, 'evtx_powershell', False)
            no_powershell = getattr(args, 'evtx_no_powershell', False)
            recursive = getattr(args, 'evtx_recursive', False)
            max_events = getattr(args, 'evtx_max', None)
            print(args)
            output = getattr(args, 'output', None)

            # Initialize parser
            evtx = ToolboxEvtx(filepath)
            
            # Parse based on type
            if is_directory:
                print(f"[*] Directory mode - parsing all EVTX files...")
                if evtx.parse_directory(
                    start_date=start_date,
                    end_date=end_date,
                    event_ids=event_ids,
                    forensic_only=not all_events,
                    parse_powershell=not no_powershell,
                    recursive=recursive
                ):
                    if powershell:
                        evtx._print_powershell_results()
                    else:
                        evtx.print_summary()
                        evtx.print_results(max_events=max_events)
                    
                    if output:
                        if output.endswith('.json'):
                            evtx.export_json(output, powershell_only=powershell)
                        elif output.endswith('.csv'):
                            evtx.export_csv(output, powershell_only=powershell)
                        else:
                            print(f"[!] Unsupported output format. Use .json or .csv")
                else:
                    print("[!] Failed to parse directory")
            else:
                print(f"[*] Parsing EVTX file...")
                if evtx.parse(
                    start_date=start_date,
                    end_date=end_date,
                    event_ids=event_ids,
                    forensic_only=not all_events,
                    parse_powershell=not no_powershell
                ):
                    evtx.print_results(max_events=max_events, powershell_only=powershell)
                    
                    if output:
                        if output.endswith('.json'):
                            evtx.export_json(output, powershell_only=powershell)
                        elif output.endswith('.csv'):
                            evtx.export_csv(output, powershell_only=powershell)
                        else:
                            print(f"[!] Unsupported output format. Use .json or .csv")
                else:
                    print("[!] Failed to parse EVTX file")
        
        except ImportError:
            print("[!] python-evtx library not installed")
            print("[*] Install with: pip install python-evtx")
        except Exception as e:
            print(f"[!] Error: {e}")
            if self.verbose:
                import traceback
                traceback.print_exc()


def main():
    """Main entry point for the forensic toolbox"""
    parser = argparse.ArgumentParser(
        description='Forensic Toolbox - Automatic Windows Forensic Artifacts Parser',
        epilog='''
Examples:
  # Automatically detect and parse any supported file
  forensic-toolbox evidence.lnk
  forensic-toolbox CALC.EXE-12345.pf
  forensic-toolbox SOFTWARE
  
  # Specify registry type explicitly
  forensic-toolbox REGISTRY_FILE --type SOFTWARE
  
  # Export results to file
  forensic-toolbox SOFTWARE --output results.json
  forensic-toolbox NTUSER.DAT --output user_activity.csv
  
  # Process multiple files
  forensic-toolbox file1.lnk file2.pf NTUSER.DAT
         # EVTX with date range
  forensic-toolbox Security.evtx --evtx-start 2024-01-01 --evtx-end 2024-01-31
  
  # EVTX specific event IDs
  forensic-toolbox Security.evtx --evtx-events 4624 4625 4688
  
  # EVTX PowerShell commands
  forensic-toolbox PowerShell-Operational.evtx --evtx-powershell
  
  # Parse EVTX directory
  forensic-toolbox C:\\logs --evtx-recursive --output timeline.json
  
  # Export results
  forensic-toolbox SOFTWARE --output results.json
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'files',
        nargs='+',
        help='File(s) or directory to analyze'
    )
    
    # General options (apply to all file types)
    general_group = parser.add_argument_group('General Options')
    
    general_group.add_argument(
        '-o', '--output',
        help='Output file (.json or .csv depending on file type)'
    )
    
    general_group.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    general_group.add_argument(
        '--version',
        action='version',
        version='Forensic Toolbox v1.0.0'
    )
    
    # Registry-specific options
    registry_group = parser.add_argument_group('Registry Options (for registry hives only)')
    
    registry_group.add_argument(
        '-t', '--type',
        choices=['SOFTWARE', 'SYSTEM', 'SAM', 'NTUSER', 'SECURITY', 'USRCLASS'],
        help='Registry hive type'
    )
    
    # EVTX-specific options
    evtx_group = parser.add_argument_group('EVTX Options (for .evtx files and log directories only)')
    
    evtx_group.add_argument(
        '--evtx-start',
        metavar='DATE',
        help='Start date filter (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)'
    )
    
    evtx_group.add_argument(
        '--evtx-end',
        metavar='DATE',
        help='End date filter (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)'
    )
    
    evtx_group.add_argument(
        '--evtx-events',
        nargs='+',
        type=int,
        metavar='ID',
        help='Specific event IDs to extract (e.g., --evtx-events 4624 4625)'
    )
    
    evtx_group.add_argument(
        '--evtx-all',
        action='store_true',
        help='Extract all events (not just forensically significant ones)'
    )
    
    evtx_group.add_argument(
        '--evtx-powershell',
        action='store_true',
        help='Show PowerShell commands only'
    )
    
    evtx_group.add_argument(
        '--evtx-no-powershell',
        action='store_true',
        help='Skip PowerShell command extraction'
    )
    
    evtx_group.add_argument(
        '--evtx-recursive',
        action='store_true',
        help='Search subdirectories when parsing a directory'
    )
    
    evtx_group.add_argument(
        '--evtx-max',
        type=int,
        metavar='N',
        help='Maximum number of events to display'
    )
    
    args = parser.parse_args()
    
    # Initialize toolbox
    toolbox = ForensicToolbox()
    toolbox.verbose = args.verbose
    
    # Process each file
    success_count = 0
    total_count = len(args.files)
    
    for filepath in args.files:
        print(args)
        if toolbox.process_file(filepath, args):
            success_count += 1
    
    # Summary
    if total_count > 1:
        print(f"\n{'='*70}")
        print(f"Processed {success_count}/{total_count} files successfully")
        print(f"{'='*70}\n")
    
    # Exit with appropriate code
    sys.exit(0 if success_count == total_count else 1)


if __name__ == '__main__':
    main()