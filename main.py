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
        
        # Check file extension
        ext = path.suffix.lower()
        
        if ext == '.lnk':
            return ('lnk', None)
        
        if ext == '.pf':
            return ('prefetch', None)
        
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
    
    def process_file(self, filepath, registry_type=None, output=None):
        """
        Process a forensic artifact file
        
        Args:
            filepath: Path to the file
            registry_type: Override registry type detection
            output: Output file path (optional)
        """
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
                self._process_lnk(filepath, output)
            
            elif file_type == 'prefetch':
                self._process_prefetch(filepath, output)
            
            elif file_type == 'registry':
                # Use provided registry type or detected type
                hive_type = registry_type or detected_info
                if not hive_type:
                    print("[!] Cannot determine registry hive type.")
                    print("[*] Please specify with --type option")
                    print("[*] Valid types: SOFTWARE, SYSTEM, SAM, NTUSER, SECURITY, USRCLASS")
                    return False
                
                self._process_registry(filepath, hive_type, output)
            
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
    
    def _process_lnk(self, filepath, output):
        """Process Windows shortcut (.lnk) file"""
        print(f"[*] Parsing LNK file...")
        lnk = ToolboxLnk(filepath)
        
        if output:
            print(f"[*] Output functionality not yet implemented for LNK files")
    
    def _process_prefetch(self, filepath, output):
        """Process Windows prefetch (.pf) file"""
        print(f"[*] Parsing Prefetch file...")
        
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
    
    def _process_registry(self, filepath, hive_type, output):
        """Process Windows registry hive"""
        print(f"[*] Registry hive type: {hive_type}")
        print(f"[*] Extracting forensic artifacts...")
        
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
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        'files',
        nargs='+',
        help='File(s) to analyze (supports .lnk, .pf, registry hives)'
    )
    
    parser.add_argument(
        '-t', '--type',
        choices=['SOFTWARE', 'SYSTEM', 'SAM', 'NTUSER', 'SECURITY', 'USRCLASS'],
        help='Registry hive type (only needed if auto-detection fails)'
    )
    
    parser.add_argument(
        '-o', '--output',
        help='Output file (.json or .csv for registry, .json for prefetch)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version='Forensic Toolbox v1.0.0'
    )
    
    args = parser.parse_args()
    
    # Initialize toolbox
    toolbox = ForensicToolbox()
    toolbox.verbose = args.verbose
    
    # Process each file
    success_count = 0
    total_count = len(args.files)
    
    for filepath in args.files:
        if toolbox.process_file(filepath, args.type, args.output):
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