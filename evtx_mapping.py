"""
Windows Event Log Forensic Event ID Mappings

Contains forensically significant Event IDs organized by log type.
Used by the EVTX parser to filter and describe events.

References:
- Microsoft Security Auditing Documentation
- MITRE ATT&CK Framework
- Digital Forensics community best practices
"""

# Forensically significant Event IDs by log type
FORENSIC_EVENT_IDS = {
    'Security': {
        # ==================== Account Logon ====================
        4624: 'Successful Logon',
        4625: 'Failed Logon',
        4634: 'Logoff',
        4647: 'User Initiated Logoff',
        4648: 'Logon with Explicit Credentials (RunAs)',
        4672: 'Special Privileges Assigned to New Logon',
        4768: 'Kerberos TGT Request',
        4769: 'Kerberos Service Ticket Request',
        4770: 'Kerberos Service Ticket Renewed',
        4771: 'Kerberos Pre-authentication Failed',
        4776: 'Credential Validation (NTLM)',
        4778: 'Session Reconnected',
        4779: 'Session Disconnected',
        
        # ==================== Account Management ====================
        4720: 'User Account Created',
        4722: 'User Account Enabled',
        4723: 'Password Change Attempt',
        4724: 'Password Reset Attempt',
        4725: 'User Account Disabled',
        4726: 'User Account Deleted',
        4727: 'Global Security Group Created',
        4728: 'Member Added to Global Security Group',
        4729: 'Member Removed from Global Security Group',
        4730: 'Global Security Group Deleted',
        4731: 'Local Security Group Created',
        4732: 'Member Added to Local Security Group',
        4733: 'Member Removed from Local Security Group',
        4734: 'Local Security Group Deleted',
        4735: 'Local Security Group Changed',
        4737: 'Global Security Group Changed',
        4738: 'User Account Changed',
        4740: 'User Account Locked Out',
        4741: 'Computer Account Created',
        4742: 'Computer Account Changed',
        4743: 'Computer Account Deleted',
        4767: 'User Account Unlocked',
        4780: 'ACL Set on Admin Group Members',
        4781: 'Account Name Changed',
        4794: 'Directory Services Restore Mode Password Set',
        
        # ==================== Process Tracking ====================
        4688: 'Process Creation',
        4689: 'Process Termination',
        
        # ==================== Object Access ====================
        4656: 'Handle to Object Requested',
        4658: 'Handle to Object Closed',
        4660: 'Object Deleted',
        4663: 'Object Access Attempt',
        4670: 'Permissions Changed on Object',
        5140: 'Network Share Object Accessed',
        5142: 'Network Share Object Added',
        5143: 'Network Share Object Modified',
        5144: 'Network Share Object Deleted',
        5145: 'Network Share Object Checked',
        
        # ==================== Policy Change ====================
        4704: 'User Right Assigned',
        4705: 'User Right Removed',
        4706: 'Trust to Domain Created',
        4707: 'Trust to Domain Removed',
        4713: 'Kerberos Policy Changed',
        4715: 'Audit Policy (SACL) Changed on Object',
        4716: 'Trusted Domain Information Modified',
        4717: 'System Security Access Granted',
        4718: 'System Security Access Removed',
        4719: 'System Audit Policy Changed',
        4739: 'Domain Policy Changed',
        4817: 'Auditing Settings on Object Changed',
        
        # ==================== Privilege Use ====================
        4673: 'Sensitive Privilege Use',
        4674: 'Operation Attempted on Privileged Object',
        
        # ==================== System Events ====================
        1100: 'Event Log Service Shutdown',
        1102: 'Audit Log Cleared',
        1104: 'Security Log Full',
        1105: 'Event Log Automatic Backup',
        1108: 'Event Logging Service Error',
        4608: 'Windows Starting Up',
        4609: 'Windows Shutting Down',
        4610: 'Authentication Package Loaded',
        4611: 'Trusted Logon Process Registered',
        4612: 'Internal Resources for Auditing',
        4614: 'Notification Package Loaded',
        4615: 'Invalid Use of LPC Port',
        4616: 'System Time Changed',
        4618: 'Monitored Security Event Pattern',
        4621: 'Administrator Recovered System from CrashOnAuditFail',
        
        # ==================== Scheduled Tasks ====================
        4698: 'Scheduled Task Created',
        4699: 'Scheduled Task Deleted',
        4700: 'Scheduled Task Enabled',
        4701: 'Scheduled Task Disabled',
        4702: 'Scheduled Task Updated',
        
        # ==================== Windows Filtering Platform ====================
        5031: 'Windows Firewall Blocked Application',
        5152: 'Windows Filtering Platform Blocked Packet',
        5153: 'Windows Filtering Platform Blocked Connection',
        5154: 'Windows Filtering Platform Permitted Application',
        5155: 'Windows Filtering Platform Blocked Application',
        5156: 'Windows Filtering Platform Permitted Connection',
        5157: 'Windows Filtering Platform Blocked Connection',
        5158: 'Windows Filtering Platform Permitted Bind',
        5159: 'Windows Filtering Platform Blocked Bind',
    },
    
    'System': {
        # ==================== System Boot/Shutdown ====================
        6005: 'Event Log Service Started',
        6006: 'Event Log Service Stopped',
        6008: 'Unexpected Shutdown',
        6009: 'System Boot',
        6013: 'System Uptime',
        12: 'System Startup',
        13: 'System Shutdown',
        
        # ==================== Service Events ====================
        7030: 'Service Installation/Configuration',
        7034: 'Service Crashed Unexpectedly',
        7035: 'Service Control Success',
        7036: 'Service State Change (Start/Stop)',
        7040: 'Service Startup Type Changed',
        7045: 'Service Installed',
        
        # ==================== Service Failures ====================
        7000: 'Service Failed to Start',
        7001: 'Service Dependency Failed',
        7009: 'Service Timeout',
        7011: 'Service Timeout (30000ms)',
        7022: 'Service Hung on Starting',
        7023: 'Service Terminated with Error',
        7024: 'Service Terminated with Service-Specific Error',
        7026: 'Boot-Start/System-Start Driver Failed to Load',
        7031: 'Service Crashed',
        7032: 'Service Control Manager Attempted Recovery',
        7034: 'Service Crashed',
        
        # ==================== Time Changes ====================
        1: 'System Time Changed',
        
        # ==================== Power Events ====================
        41: 'System Reboot Without Proper Shutdown (Kernel-Power)',
        42: 'System Entering Sleep',
        107: 'System Wakeup Source',
        1074: 'System Shutdown/Restart Initiated',
        1076: 'Shutdown Reason',
        
        # ==================== User32 Events ====================
        1: 'System Time Changed',
        
        # ==================== Disk/Volume Events ====================
        55: 'File System Corruption Detected',
        
        # ==================== Application Crashes ====================
        1000: 'Application Error',
        1001: 'Windows Error Reporting',
    },
    
    'Application': {
        # ==================== Application Errors ====================
        1000: 'Application Error',
        1001: 'Application Hang',
        1002: 'Application Error Reporting',
        
        # ==================== Windows Error Reporting ====================
        1001: 'Fault Bucket',
    },
    
    'Microsoft-Windows-PowerShell/Operational': {
        # ==================== PowerShell Detailed Logging ====================
        4103: 'Module Logging (Pipeline Execution)',
        4104: 'Script Block Logging',
        4105: 'Script Start',
        4106: 'Script Stop',
        53504: 'Windows PowerShell Started',
    },
    
    'Windows PowerShell': {
        # ==================== Classic PowerShell ====================
        400: 'Engine State Changed to Available',
        403: 'Engine State Changed to Stopped',
        500: 'Command Started',
        501: 'Command Stopped',
        600: 'Provider Lifecycle (WSMan)',
        800: 'Pipeline Execution Details',
    },
    
    'Microsoft-Windows-TaskScheduler/Operational': {
        # ==================== Scheduled Tasks ====================
        100: 'Task Started',
        102: 'Task Completed',
        106: 'Task Registered',
        107: 'Task Triggered',
        108: 'Task Triggered on Event',
        110: 'Task Triggered by User',
        129: 'Task Created',
        140: 'Task Updated',
        141: 'Task Deleted',
        142: 'Task Disabled',
        200: 'Task Executed/Action Started',
        201: 'Task Action Completed',
        202: 'Task Completed',
        203: 'Task Action Failed to Start',
        204: 'Task Action Failed to Complete',
        324: 'Task Scheduler Launched Task Instance',
        325: 'Task Scheduler Queued Task Instance',
        326: 'Task Scheduler Launched Task Process',
    },
    
    'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational': {
        # ==================== RDP/Terminal Services ====================
        21: 'RDP Session Logon Success',
        22: 'RDP Shell Start Notification',
        23: 'RDP Session Logoff',
        24: 'RDP Session Disconnected',
        25: 'RDP Session Reconnection Success',
        39: 'RDP Session Disconnected by Session',
        40: 'RDP Session Disconnected by User',
    },
    
    'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational': {
        # ==================== RDP Connection Manager ====================
        1149: 'RDP User Authentication Successful',
        261: 'RDP Connection Received',
    },
    
    'Microsoft-Windows-Windows Defender/Operational': {
        # ==================== Windows Defender ====================
        1000: 'Scan Started',
        1001: 'Scan Completed',
        1002: 'Scan Stopped',
        1005: 'Scan Failed',
        1006: 'Malware Detected',
        1007: 'Malware Action Taken',
        1008: 'Malware Action Failed',
        1009: 'Malware Quarantined',
        1010: 'Malware Not Quarantined',
        1013: 'History Deleted',
        1116: 'Malware Detected (Newer)',
        1117: 'Malware Action Taken (Newer)',
        1118: 'Malware Action Failed (Newer)',
        1119: 'Critical Error',
        5001: 'Real-time Protection Disabled',
        5004: 'Real-time Protection Configuration Changed',
        5007: 'Configuration Changed',
        5010: 'Scanning Malware Disabled',
        5012: 'Scanning Viruses Disabled',
    },
    
    'Microsoft-Windows-Sysmon/Operational': {
        # ==================== Sysmon (If Installed) ====================
        1: 'Process Creation',
        2: 'Process Changed File Creation Time',
        3: 'Network Connection',
        4: 'Sysmon Service State Changed',
        5: 'Process Terminated',
        6: 'Driver Loaded',
        7: 'Image Loaded (DLL)',
        8: 'CreateRemoteThread Detected',
        9: 'RawAccessRead Detected',
        10: 'Process Access',
        11: 'File Created',
        12: 'Registry Object Added or Deleted',
        13: 'Registry Value Set',
        14: 'Registry Object Renamed',
        15: 'File Stream Created',
        16: 'Sysmon Configuration Changed',
        17: 'Pipe Created',
        18: 'Pipe Connected',
        19: 'WMI Event Filter Activity',
        20: 'WMI Event Consumer Activity',
        21: 'WMI Event Consumer to Filter Activity',
        22: 'DNS Query',
        23: 'File Delete',
        24: 'Clipboard Changed',
        25: 'Process Tampering',
        26: 'File Delete Logged',
        27: 'File Block Executable',
        28: 'File Block Shredding',
    },
    
    'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall': {
        # ==================== Firewall ====================
        2003: 'Firewall Rule Changed',
        2004: 'Firewall Rule Added',
        2005: 'Firewall Rule Modified',
        2006: 'Firewall Rule Deleted',
        2033: 'Firewall Rule Add Failed',
    },
    
    'Microsoft-Windows-SMBServer/Security': {
        # ==================== SMB File Shares ====================
        1009: 'Client Disconnected',
    },
    
    'Microsoft-Windows-NTLM/Operational': {
        # ==================== NTLM Authentication ====================
        8001: 'NTLM Authentication Blocked',
        8002: 'NTLM Authentication Audit',
        8003: 'NTLM Authentication in Domain',
        8004: 'DC Blocked NTLM Authentication',
    },
    
    'Microsoft-Windows-WMI-Activity/Operational': {
        # ==================== WMI Activity ====================
        5857: 'WMI Activity Detected',
        5858: 'WMI Error',
        5859: 'WMI Error',
        5860: 'WMI Registration of Temporary Event Consumer',
        5861: 'WMI Registration of Permanent Event Consumer',
    },
    
    'Microsoft-Windows-Bits-Client/Operational': {
        # ==================== BITS (Background Intelligent Transfer) ====================
        3: 'BITS Transfer Created',
        59: 'BITS Transfer Started',
        60: 'BITS Transfer Stopped',
        61: 'BITS Transfer Completed',
    },
    
    'Microsoft-Windows-AppLocker/EXE and DLL': {
        # ==================== AppLocker ====================
        8002: 'Executable Allowed',
        8003: 'Executable Blocked',
        8004: 'Executable Audited',
    },
    
    'Microsoft-Windows-CodeIntegrity/Operational': {
        # ==================== Code Integrity ====================
        3001: 'Code Integrity Check Failed',
        3002: 'Code Integrity Check Failed (Audit Mode)',
        3004: 'Code Integrity Blocked Untrusted Driver',
        3076: 'Code Integrity Determined File Hash',
        3077: 'Code Integrity Determined Signature',
    },
}

# Category mappings for better organization
EVENT_CATEGORIES = {
    'account_logon': {
        'description': 'Account Logon and Authentication',
        'events': [4624, 4625, 4634, 4647, 4648, 4768, 4769, 4776, 4778, 4779]
    },
    'account_management': {
        'description': 'Account and Group Management',
        'events': [4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4738, 4740, 4767]
    },
    'process_execution': {
        'description': 'Process Creation and Termination',
        'events': [4688, 4689, 1]  # Sysmon 1 included
    },
    'persistence': {
        'description': 'Persistence Mechanisms',
        'events': [4698, 4699, 4700, 4701, 4702, 7045, 106, 140, 141, 200]
    },
    'privilege_escalation': {
        'description': 'Privilege Escalation',
        'events': [4672, 4673, 4728, 4732]
    },
    'lateral_movement': {
        'description': 'Lateral Movement',
        'events': [4648, 21, 22, 24, 25, 1149]
    },
    'credential_access': {
        'description': 'Credential Access',
        'events': [4768, 4769, 4776]
    },
    'anti_forensics': {
        'description': 'Anti-Forensics and Log Manipulation',
        'events': [1102, 4616, 4719, 1100, 1104]
    },
    'network': {
        'description': 'Network Activity',
        'events': [3, 22, 5140, 5142, 5143, 5144, 5145, 5156]  # Sysmon 3, 22
    },
    'malware': {
        'description': 'Malware Detection',
        'events': [1006, 1007, 1116, 1117]
    },
}

# Logon Type descriptions (for Event ID 4624)
LOGON_TYPES = {
    2: 'Interactive (Local Console)',
    3: 'Network (File Share, Network Drive)',
    4: 'Batch (Scheduled Task)',
    5: 'Service (Service Logon)',
    7: 'Unlock (Workstation Unlock)',
    8: 'NetworkCleartext (IIS, Network with Cleartext)',
    9: 'NewCredentials (RunAs /netonly)',
    10: 'RemoteInteractive (RDP, Terminal Services)',
    11: 'CachedInteractive (Cached Domain Credentials)',
}

# Common suspicious PowerShell patterns
SUSPICIOUS_POWERSHELL_PATTERNS = [
    'Invoke-Expression',
    'IEX',
    'Invoke-Command',
    'DownloadString',
    'DownloadFile',
    'FromBase64String',
    'EncodedCommand',
    '-enc',
    '-e ',
    'WindowStyle Hidden',
    'Invoke-Mimikatz',
    'Invoke-Obfuscation',
    'Net.WebClient',
    'WebClient',
    'System.Reflection.Assembly::Load',
    'Invoke-Shellcode',
    'Invoke-WMIMethod',
    'Invoke-CimMethod',
    'Add-Type',
    'Start-Process',
    'Start-Job',
    'Register-ScheduledTask',
    'New-Service',
    'Set-Service',
    'Set-ItemProperty',
    'New-ItemProperty',
    'Set-MpPreference',
    'Add-MpPreference',
    'Set-ExecutionPolicy Bypass',
    'ExecutionPolicy Bypass',
]

# Suspicious process names (for Event ID 4688)
SUSPICIOUS_PROCESSES = [
    'mimikatz',
    'procdump',
    'pwdump',
    'gsecdump',
    'wce.exe',
    'psexec',
    'paexec',
    'remcom',
    'winexe',
    'netcat',
    'nc.exe',
    'ncat',
    'pscp',
    'plink',
    'wmic',
    'cscript',
    'wscript',
    'mshta',
    'regsvr32',
    'rundll32',
    'certutil',
    'bitsadmin',
]

# Service names commonly used for persistence
PERSISTENCE_SERVICES = [
    'PSEXESVC',
    'RemoteRegistry',
    'RemoteAccess',
    'TermService',
]


def get_event_description(log_type: str, event_id: int) -> str:
    """
    Get description for a specific event ID
    
    Args:
        log_type: Type of log (e.g., 'Security', 'System')
        event_id: Event ID number
        
    Returns:
        Description string or 'Unknown Event'
    """
    return FORENSIC_EVENT_IDS.get(log_type, {}).get(event_id, 'Unknown Event')


def get_all_forensic_ids(log_type: str = None) -> dict:
    """
    Get all forensic event IDs, optionally filtered by log type
    
    Args:
        log_type: Optional log type to filter by
        
    Returns:
        Dictionary of event IDs and descriptions
    """
    if log_type:
        return FORENSIC_EVENT_IDS.get(log_type, {})
    return FORENSIC_EVENT_IDS


def is_forensic_event(log_type: str, event_id: int) -> bool:
    """
    Check if an event ID is forensically significant
    
    Args:
        log_type: Type of log
        event_id: Event ID to check
        
    Returns:
        True if forensically significant
    """
    return event_id in FORENSIC_EVENT_IDS.get(log_type, {})


def get_logon_type_description(logon_type: int) -> str:
    """
    Get description for Windows logon type
    
    Args:
        logon_type: Logon type number (from Event ID 4624)
        
    Returns:
        Description string
    """
    return LOGON_TYPES.get(logon_type, f'Unknown Logon Type ({logon_type})')


def check_suspicious_powershell(command: str) -> list:
    """
    Check if PowerShell command contains suspicious patterns
    
    Args:
        command: PowerShell command string
        
    Returns:
        List of matched suspicious patterns
    """
    matches = []
    command_lower = command.lower()
    
    for pattern in SUSPICIOUS_POWERSHELL_PATTERNS:
        if pattern.lower() in command_lower:
            matches.append(pattern)
    
    return matches


def check_suspicious_process(process_name: str) -> bool:
    """
    Check if process name is commonly associated with attacks
    
    Args:
        process_name: Process name or path
        
    Returns:
        True if suspicious
    """
    process_lower = process_name.lower()
    
    for suspicious in SUSPICIOUS_PROCESSES:
        if suspicious in process_lower:
            return True
    
    return False