"""
Windows Event Log (EVTX) Parser for Digital Forensics

Parses Windows Event Log files (.evtx) and extracts forensically significant events.
Includes special handling for PowerShell command-line logging and directory parsing.

Features:
- Forensically significant event ID filtering
- PowerShell ScriptBlock and command-line extraction
- Date range filtering
- Directory parsing (bulk analysis)
- Multiple output formats (console, JSON, CSV)
- Suspicious pattern detection

Dependencies:
    pip install python-evtx
    
Example:
    from Toolbox.toolbox_evtx import ToolboxEvtx
    
    # Single file
    evtx = ToolboxEvtx('Security.evtx')
    evtx.parse(start_date='2024-01-01', end_date='2024-01-31')
    evtx.print_results()
    
    # Directory
    evtx = ToolboxEvtx('C:/Windows/System32/winevt/Logs')
    evtx.parse_directory()
    evtx.print_summary()
"""

import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from collections import defaultdict

# Import event mappings
try:
    from evtx_mapping import (
        FORENSIC_EVENT_IDS,
        get_event_description,
        get_logon_type_description,
        check_suspicious_powershell,
        check_suspicious_process,
        SUSPICIOUS_POWERSHELL_PATTERNS
    )
except ImportError:
    # If running from Toolbox package
    try:
        import sys
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from evtx_mapping import (
            FORENSIC_EVENT_IDS,
            get_event_description,
            get_logon_type_description,
            check_suspicious_powershell,
            check_suspicious_process,
            SUSPICIOUS_POWERSHELL_PATTERNS
        )
    except ImportError:
        print("[!] Warning: evtx_mapping.py not found. Event descriptions will be limited.")
        FORENSIC_EVENT_IDS = {}
        def get_event_description(log_type, event_id): return f"Event {event_id}"
        def get_logon_type_description(logon_type): return f"Type {logon_type}"
        def check_suspicious_powershell(cmd): return []
        def check_suspicious_process(proc): return False
        SUSPICIOUS_POWERSHELL_PATTERNS = []

try:
    import Evtx.Evtx as evtx
    import Evtx.Views as e_views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False


class ToolboxEvtx:
    """
    Windows Event Log Parser with forensic focus
    
    Attributes:
        evtx_path: Path to EVTX file or directory
        is_directory: Whether parsing a directory
        events: List of parsed events
        event_counts: Count of events by ID
        powershell_commands: Extracted PowerShell commands
        suspicious_powershell: PowerShell commands with suspicious patterns
    """
    
    def __init__(self, evtx_path: str):
        """
        Initialize the EVTX parser
        
        Args:
            evtx_path: Path to EVTX file or directory
        """
        if not EVTX_AVAILABLE:
            raise ImportError(
                "python-evtx library not installed. "
                "Install with: pip install python-evtx"
            )
        
        self.evtx_path = Path(evtx_path)
        
        if not self.evtx_path.exists():
            raise FileNotFoundError(f"Path not found: {evtx_path}")
        
        self.is_directory = self.evtx_path.is_dir()
        
        # Storage for parsed data
        self.events = []
        self.event_counts = defaultdict(int)
        self.powershell_commands = []
        self.suspicious_powershell = []
        self.filtered_count = 0
        self.total_count = 0
        
        # For directory parsing
        self.files_processed = []
        self.files_failed = []
        
        # Determine log type from filename (if single file)
        if not self.is_directory:
            self.log_type = self._detect_log_type(self.evtx_path)
            self.forensic_ids = FORENSIC_EVENT_IDS.get(self.log_type, {})
        else:
            self.log_type = 'Multiple'
            self.forensic_ids = {}
    
    def _detect_log_type(self, filepath: Path) -> str:
        """Detect log type from filename"""
        filename = filepath.name.lower()
        
        if 'security' in filename:
            return 'Security'
        elif 'system' in filename:
            return 'System'
        elif 'application' in filename:
            return 'Application'
        elif 'powershell' in filename and 'operational' in filename:
            return 'Microsoft-Windows-PowerShell/Operational'
        elif 'powershell' in filename:
            return 'Windows PowerShell'
        elif 'taskscheduler' in filename:
            return 'Microsoft-Windows-TaskScheduler/Operational'
        elif 'terminalservices' in filename or 'rdp' in filename:
            return 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'
        elif 'defender' in filename:
            return 'Microsoft-Windows-Windows Defender/Operational'
        elif 'sysmon' in filename:
            return 'Microsoft-Windows-Sysmon/Operational'
        else:
            return 'Unknown'
    
    def parse_directory(self,
                       start_date: Optional[str] = None,
                       end_date: Optional[str] = None,
                       event_ids: Optional[List[int]] = None,
                       forensic_only: bool = True,
                       parse_powershell: bool = True,
                       recursive: bool = False) -> bool:
        """
        Parse all EVTX files in a directory
        
        Args:
            start_date: Start date filter (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
            end_date: End date filter
            event_ids: List of specific event IDs to extract
            forensic_only: Only extract forensically significant events
            parse_powershell: Extract PowerShell commands
            recursive: Search subdirectories
            
        Returns:
            True if at least one file parsed successfully
        """
        if not self.is_directory:
            print("[!] Path is not a directory. Use parse() for single files.")
            return False
        
        print(f"\n[*] Scanning directory: {self.evtx_path}")
        
        # Find all .evtx files
        if recursive:
            evtx_files = list(self.evtx_path.rglob('*.evtx'))
        else:
            evtx_files = list(self.evtx_path.glob('*.evtx'))
        
        if not evtx_files:
            print(f"[!] No EVTX files found in {self.evtx_path}")
            return False
        
        print(f"[*] Found {len(evtx_files)} EVTX file(s)")
        print()
        
        # Parse each file
        for i, evtx_file in enumerate(evtx_files, 1):
            print(f"[{i}/{len(evtx_files)}] Processing: {evtx_file.name}")
            
            try:
                # Create temporary parser for this file
                temp_parser = ToolboxEvtx(str(evtx_file))
                
                if temp_parser.parse(
                    start_date=start_date,
                    end_date=end_date,
                    event_ids=event_ids,
                    forensic_only=forensic_only,
                    parse_powershell=parse_powershell,
                    quiet=True
                ):
                    # Merge results
                    self.events.extend(temp_parser.events)
                    for event_id, count in temp_parser.event_counts.items():
                        self.event_counts[event_id] += count
                    self.powershell_commands.extend(temp_parser.powershell_commands)
                    self.suspicious_powershell.extend(temp_parser.suspicious_powershell)
                    self.filtered_count += temp_parser.filtered_count
                    self.total_count += temp_parser.total_count
                    
                    self.files_processed.append({
                        'file': evtx_file.name,
                        'events': temp_parser.filtered_count,
                        'total': temp_parser.total_count
                    })
                else:
                    self.files_failed.append(evtx_file.name)
            
            except Exception as e:
                print(f"    [!] Error: {e}")
                self.files_failed.append(evtx_file.name)
        
        print()
        print(f"[+] Processed {len(self.files_processed)} files successfully")
        if self.files_failed:
            print(f"[!] Failed to process {len(self.files_failed)} files")
        print(f"[+] Total events extracted: {self.filtered_count:,} from {self.total_count:,}")
        
        # Sort events by timestamp
        self.events.sort(key=lambda x: x['timestamp'])
        
        return len(self.files_processed) > 0
    
    def parse(self, 
              start_date: Optional[str] = None,
              end_date: Optional[str] = None,
              event_ids: Optional[List[int]] = None,
              forensic_only: bool = True,
              parse_powershell: bool = True,
              quiet: bool = False) -> bool:
        """
        Parse the EVTX file
        
        Args:
            start_date: Start date filter (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)
            end_date: End date filter
            event_ids: List of specific event IDs to extract
            forensic_only: Only extract forensically significant events
            parse_powershell: Extract PowerShell commands
            quiet: Suppress progress output
            
        Returns:
            True if parsing succeeded
        """
        if self.is_directory:
            print("[!] Path is a directory. Use parse_directory() instead.")
            return False
        
        try:
            if not quiet:
                print(f"[*] Parsing EVTX file: {self.evtx_path.name}")
                print(f"[*] Detected log type: {self.log_type}")
            
            # Parse date filters
            start_dt = self._parse_date(start_date) if start_date else None
            end_dt = self._parse_date(end_date) if end_date else None
            
            if not quiet:
                if start_dt:
                    print(f"[*] Start date filter: {start_dt}")
                if end_dt:
                    print(f"[*] End date filter: {end_dt}")
            
            # Determine which event IDs to extract
            if event_ids:
                target_ids = set(event_ids)
                if not quiet:
                    print(f"[*] Filtering for Event IDs: {sorted(target_ids)}")
            elif forensic_only:
                target_ids = set(self.forensic_ids.keys())
                if not quiet and target_ids:
                    print(f"[*] Extracting {len(target_ids)} forensically significant event types")
            else:
                target_ids = None
                if not quiet:
                    print(f"[*] Extracting all events")
            
            # Parse EVTX file
            with evtx.Evtx(str(self.evtx_path)) as log:
                for record in log.records():
                    self.total_count += 1
                    
                    try:
                        # Parse XML
                        xml_str = record.xml()
                        root = ET.fromstring(xml_str)
                        
                        # Extract event data
                        event = self._parse_event_xml(root)
                        
                        if not event:
                            continue
                        
                        # Apply date filters
                        if start_dt and event['timestamp'] < start_dt:
                            continue
                        if end_dt and event['timestamp'] > end_dt:
                            continue
                        
                        # Apply event ID filter
                        if target_ids and event['event_id'] not in target_ids:
                            continue
                        
                        self.filtered_count += 1
                        self.event_counts[event['event_id']] += 1
                        
                        # Add forensic description if available
                        event['description'] = get_event_description(self.log_type, event['event_id'])
                        
                        # Add source file for directory parsing
                        event['source_file'] = self.evtx_path.name
                        
                        self.events.append(event)
                        
                        # Special handling for PowerShell events
                        if parse_powershell and event['event_id'] in [4103, 4104]:
                            self._extract_powershell_commands(event)
                        
                        # Check for suspicious processes in 4688 events
                        if event['event_id'] == 4688:
                            self._check_suspicious_process(event)
                    
                    except Exception as e:
                        if '--verbose' in sys.argv:
                            print(f"[!] Error parsing record: {e}")
                        continue
            
            if not quiet:
                print(f"[+] Parsed {self.total_count} total events")
                print(f"[+] Extracted {self.filtered_count} matching events")
                if self.powershell_commands:
                    print(f"[+] Found {len(self.powershell_commands)} PowerShell commands")
                if self.suspicious_powershell:
                    print(f"[!] Found {len(self.suspicious_powershell)} SUSPICIOUS PowerShell commands")
            
            return True
            
        except Exception as e:
            print(f"[!] Error parsing EVTX file: {e}")
            return False
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string to datetime object"""
        formats = [
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d %H:%M',
            '%Y-%m-%d',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str, fmt)
            except ValueError:
                continue
        
        raise ValueError(f"Invalid date format: {date_str}. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
    
    def _parse_event_xml(self, root: ET.Element) -> Optional[Dict]:
        """Parse event XML and extract relevant fields"""
        try:
            ns = {'evt': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            system = root.find('evt:System', ns)
            if system is None:
                return None
            
            # Extract basic event info
            event_id_elem = system.find('evt:EventID', ns)
            event_id = int(event_id_elem.text) if event_id_elem is not None else 0
            
            time_created = system.find('evt:TimeCreated', ns)
            timestamp_str = time_created.get('SystemTime') if time_created is not None else None
            
            computer = system.find('evt:Computer', ns)
            computer_name = computer.text if computer is not None else 'Unknown'
            
            # Parse timestamp
            if timestamp_str:
                try:
                    if '.' in timestamp_str:
                        parts = timestamp_str.split('.')
                        if len(parts[1]) > 6:
                            parts[1] = parts[1][:6] + parts[1][-1]
                            timestamp_str = '.'.join(parts)
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except:
                    timestamp = datetime.now()
            else:
                timestamp = datetime.now()
            
            event = {
                'event_id': event_id,
                'timestamp': timestamp,
                'computer': computer_name,
                'event_data': {}
            }
            
            # Extract EventData or UserData
            event_data = root.find('evt:EventData', ns)
            if event_data is not None:
                for data in event_data:
                    name = data.get('Name', 'Unknown')
                    value = data.text if data.text else ''
                    event['event_data'][name] = value
            
            return event
            
        except Exception as e:
            return None
    
    def _extract_powershell_commands(self, event: Dict):
        """Extract PowerShell commands from event data"""
        try:
            event_data = event.get('event_data', {})
            command_text = None
            
            # Event ID 4104 - Script Block Logging
            if event['event_id'] == 4104:
                script_block = event_data.get('ScriptBlockText', '')
                if script_block and script_block.strip():
                    command_text = script_block.strip()
                    cmd_entry = {
                        'timestamp': event['timestamp'],
                        'computer': event['computer'],
                        'event_id': 4104,
                        'type': 'ScriptBlock',
                        'command': command_text,
                        'source_file': event.get('source_file', 'Unknown')
                    }
                    self.powershell_commands.append(cmd_entry)
            
            # Event ID 4103 - Module Logging
            elif event['event_id'] == 4103:
                payload = event_data.get('Payload', '')
                if payload and payload.strip():
                    command_text = payload.strip()
                    cmd_entry = {
                        'timestamp': event['timestamp'],
                        'computer': event['computer'],
                        'event_id': 4103,
                        'type': 'Module',
                        'command': command_text,
                        'context': event_data.get('ContextInfo', ''),
                        'source_file': event.get('source_file', 'Unknown')
                    }
                    self.powershell_commands.append(cmd_entry)
            
            # Check for suspicious patterns
            if command_text:
                suspicious_patterns = check_suspicious_powershell(command_text)
                if suspicious_patterns:
                    self.suspicious_powershell.append({
                        'timestamp': event['timestamp'],
                        'computer': event['computer'],
                        'command': command_text,
                        'patterns': suspicious_patterns,
                        'source_file': event.get('source_file', 'Unknown')
                    })
        
        except Exception as e:
            pass
    
    def _check_suspicious_process(self, event: Dict):
        """Check for suspicious process names in 4688 events"""
        try:
            event_data = event.get('event_data', {})
            new_process = event_data.get('NewProcessName', '')
            
            if new_process and check_suspicious_process(new_process):
                event['suspicious'] = True
        
        except Exception as e:
            pass
    
    def print_results(self, max_events: Optional[int] = None, powershell_only: bool = False):
        """Print parsed results"""
        print(f"\n{'='*80}")
        if self.is_directory:
            print(f"EVTX DIRECTORY ANALYSIS: {self.evtx_path}")
        else:
            print(f"EVTX ANALYSIS: {self.evtx_path.name}")
        print(f"{'='*80}")
        
        if self.is_directory:
            print(f"Files Processed: {len(self.files_processed)}")
            if self.files_failed:
                print(f"Files Failed: {len(self.files_failed)}")
        else:
            print(f"Log Type: {self.log_type}")
        
        print(f"Total Events Parsed: {self.total_count:,}")
        print(f"Events Extracted: {self.filtered_count:,}")
        
        if powershell_only:
            self._print_powershell_results()
            return
        
        # Event ID summary
        if self.event_counts:
            print(f"\n{'='*80}")
            print("EVENT ID SUMMARY")
            print(f"{'='*80}")
            
            sorted_counts = sorted(self.event_counts.items(), key=lambda x: x[1], reverse=True)
            for event_id, count in sorted_counts[:20]:  # Top 20
                # Try to get description from any log type
                desc = 'Unknown Event'
                for log_type in FORENSIC_EVENT_IDS:
                    if event_id in FORENSIC_EVENT_IDS[log_type]:
                        desc = FORENSIC_EVENT_IDS[log_type][event_id]
                        break
                print(f"  Event {event_id:5d}: {count:6,} - {desc}")
            
            if len(sorted_counts) > 20:
                print(f"  ... and {len(sorted_counts) - 20} more event types")
        
        # Suspicious findings
        if self.suspicious_powershell:
            print(f"\n{'='*80}")
            print(f"⚠️  SUSPICIOUS POWERSHELL DETECTED: {len(self.suspicious_powershell)}")
            print(f"{'='*80}")
            for i, sus in enumerate(self.suspicious_powershell[:10], 1):
                print(f"\n[{i}] {sus['timestamp'].strftime('%Y-%m-%d %H:%M:%S')} - {sus['computer']}")
                print(f"    Patterns: {', '.join(sus['patterns'])}")
                print(f"    Command: {sus['command'][:100]}{'...' if len(sus['command']) > 100 else ''}")
            
            if len(self.suspicious_powershell) > 10:
                print(f"\n    ... and {len(self.suspicious_powershell) - 10} more suspicious commands")
        
        # Detailed events
        if self.events and not powershell_only:
            display_count = min(max_events or 50, len(self.events))
            print(f"\n{'='*80}")
            print(f"DETAILED EVENTS (showing {display_count} of {len(self.events)})")
            print(f"{'='*80}\n")
            
            for i, event in enumerate(self.events[:display_count], 1):
                suspicious_marker = "⚠️ " if event.get('suspicious') else ""
                print(f"[{i}] {suspicious_marker}Event {event['event_id']} - {event.get('description', 'Unknown')}")
                print(f"    Timestamp: {event['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"    Computer: {event['computer']}")
                if self.is_directory:
                    print(f"    Source: {event.get('source_file', 'Unknown')}")
                
                # Display key event data
                if event['event_data']:
                    print(f"    Data:")
                    for key, value in list(event['event_data'].items())[:10]:
                        if value and len(str(value)) < 200:
                            print(f"      {key}: {value}")
                print()
        
        # PowerShell commands summary
        if self.powershell_commands and not powershell_only:
            print(f"\n{'='*80}")
            print(f"POWERSHELL COMMANDS: {len(self.powershell_commands)}")
            print(f"{'='*80}")
            print("(Use --powershell option to see full details)")
        
        print(f"\n{'='*80}\n")
    
    def print_summary(self):
        """Print summary when parsing directory"""
        print(f"\n{'='*80}")
        print(f"DIRECTORY ANALYSIS SUMMARY")
        print(f"{'='*80}")
        print(f"Directory: {self.evtx_path}")
        print(f"Files Processed: {len(self.files_processed)}")
        if self.files_failed:
            print(f"Files Failed: {len(self.files_failed)}")
        print(f"Total Events: {self.total_count:,}")
        print(f"Extracted Events: {self.filtered_count:,}")
        print(f"PowerShell Commands: {len(self.powershell_commands)}")
        if self.suspicious_powershell:
            print(f"⚠️  Suspicious PowerShell: {len(self.suspicious_powershell)}")
        
        if self.files_processed:
            print(f"\n{'='*80}")
            print("FILES PROCESSED")
            print(f"{'='*80}")
            for file_info in self.files_processed:
                print(f"  {file_info['file']}: {file_info['events']:,} events (of {file_info['total']:,})")
        
        print(f"\n{'='*80}\n")
    
    def _print_powershell_results(self):
        """Print PowerShell commands in detail"""
        if not self.powershell_commands:
            print("\n[!] No PowerShell commands found")
            return
        
        print(f"\n{'='*80}")
        print(f"POWERSHELL COMMAND ANALYSIS ({len(self.powershell_commands)} commands)")
        print(f"{'='*80}\n")
        
        for i, cmd in enumerate(self.powershell_commands, 1):
            # Check if suspicious
            sus_patterns = check_suspicious_powershell(cmd['command'])
            suspicious = "⚠️  SUSPICIOUS " if sus_patterns else ""
            
            print(f"[{i}] {suspicious}{cmd['type']} (Event {cmd['event_id']})")
            print(f"    Timestamp: {cmd['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"    Computer: {cmd['computer']}")
            if 'source_file' in cmd:
                print(f"    Source: {cmd['source_file']}")
            if sus_patterns:
                print(f"    Suspicious Patterns: {', '.join(sus_patterns)}")
            print(f"    Command:")
            
            # Print command with indentation
            command_lines = cmd['command'].split('\n')
            for line in command_lines[:50]:
                print(f"      {line}")
            
            if len(command_lines) > 50:
                print(f"      ... ({len(command_lines) - 50} more lines)")
            
            print()
    
    def export_json(self, output_file: str, powershell_only: bool = False):
        """Export results to JSON"""
        import json
        
        if powershell_only:
            data = {
                'source': str(self.evtx_path),
                'is_directory': self.is_directory,
                'powershell_commands': self.powershell_commands,
                'suspicious_powershell': self.suspicious_powershell
            }
        else:
            data = {
                'source': str(self.evtx_path),
                'is_directory': self.is_directory,
                'files_processed': self.files_processed if self.is_directory else None,
                'total_events': self.total_count,
                'filtered_events': self.filtered_count,
                'event_counts': dict(self.event_counts),
                'events': self.events,
                'powershell_commands': self.powershell_commands,
                'suspicious_powershell': self.suspicious_powershell
            }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, default=str)
        
        print(f"[+] Results exported to: {output_file}")
    
    def export_csv(self, output_file: str, powershell_only: bool = False):
        """Export results to CSV"""
        import csv
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if powershell_only:
                if not self.powershell_commands:
                    print("[!] No PowerShell commands to export")
                    return
                
                writer = csv.writer(f)
                writer.writerow(['Timestamp', 'Computer', 'Event ID', 'Type', 'Suspicious', 'Command', 'Source File'])
                
                for cmd in self.powershell_commands:
                    sus_patterns = check_suspicious_powershell(cmd['command'])
                    writer.writerow([
                        cmd['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                        cmd['computer'],
                        cmd['event_id'],
                        cmd['type'],
                        'Yes' if sus_patterns else 'No',
                        cmd['command'],
                        cmd.get('source_file', '')
                    ])
            else:
                writer = csv.writer(f)
                writer.writerow(['Event ID', 'Timestamp', 'Computer', 'Description', 'Suspicious', 'Event Data', 'Source File'])
                
                for event in self.events:
                    event_data_str = '; '.join([f"{k}={v}" for k, v in event['event_data'].items()])
                    writer.writerow([
                        event['event_id'],
                        event['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                        event['computer'],
                        event.get('description', ''),
                        'Yes' if event.get('suspicious') else 'No',
                        event_data_str,
                        event.get('source_file', '')
                    ])
        
        print(f"[+] Results exported to: {output_file}")


# Command-line interface
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Windows Event Log (EVTX) Parser for Digital Forensics',
        epilog='''
Examples:
  # Parse single file
  python toolbox_evtx.py Security.evtx
  
  # Parse directory
  python toolbox_evtx.py C:\\Windows\\System32\\winevt\\Logs
  
  # With date range
  python toolbox_evtx.py Security.evtx --start 2024-01-01 --end 2024-01-31
  
  # PowerShell commands only
  python toolbox_evtx.py Microsoft-Windows-PowerShell-Operational.evtx --powershell
  
  # Export to JSON
  python toolbox_evtx.py Security.evtx --output security.json
  
  # Recursive directory search
  python toolbox_evtx.py C:\\Evidence --recursive
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument('path', help='EVTX file or directory to parse')
    parser.add_argument('--start', help='Start date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--end', help='End date (YYYY-MM-DD or YYYY-MM-DD HH:MM:SS)')
    parser.add_argument('--events', nargs='+', type=int, help='Specific event IDs to extract')
    parser.add_argument('--all', action='store_true', help='Extract all events (not just forensic)')
    parser.add_argument('--powershell', action='store_true', help='Show PowerShell commands only')
    parser.add_argument('--no-powershell', action='store_true', help='Skip PowerShell parsing')
    parser.add_argument('--max', type=int, help='Maximum events to display')
    parser.add_argument('--recursive', '-r', action='store_true', help='Search subdirectories (for directory mode)')
    parser.add_argument('-o', '--output', help='Output file (.json or .csv)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    try:
        evtx = ToolboxEvtx(args.path)
        
        if evtx.is_directory:
            # Directory parsing
            if evtx.parse_directory(
                start_date=args.start,
                end_date=args.end,
                event_ids=args.events,
                forensic_only=not args.all,
                parse_powershell=not args.no_powershell,
                recursive=args.recursive
            ):
                if args.powershell:
                    evtx._print_powershell_results()
                else:
                    evtx.print_summary()
                    evtx.print_results(max_events=args.max)
                
                if args.output:
                    if args.output.endswith('.json'):
                        evtx.export_json(args.output, powershell_only=args.powershell)
                    elif args.output.endswith('.csv'):
                        evtx.export_csv(args.output, powershell_only=args.powershell)
                    else:
                        print("[!] Output file must be .json or .csv")
        else:
            # Single file parsing
            if evtx.parse(
                start_date=args.start,
                end_date=args.end,
                event_ids=args.events,
                forensic_only=not args.all,
                parse_powershell=not args.no_powershell
            ):
                evtx.print_results(max_events=args.max, powershell_only=args.powershell)
                
                if args.output:
                    if args.output.endswith('.json'):
                        evtx.export_json(args.output, powershell_only=args.powershell)
                    elif args.output.endswith('.csv'):
                        evtx.export_csv(args.output, powershell_only=args.powershell)
                    else:
                        print("[!] Output file must be .json or .csv")
    
    except Exception as e:
        print(f"[!] Error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)