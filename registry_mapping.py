"""
Digital Forensics Registry Keys Configuration
Contains registry paths and values of forensic significance for Windows analysis.
"""

# Dictionary mapping registry hive names to forensically significant key paths
forensic_keys = {
    'SOFTWARE': [
        # System Information
        'Microsoft\\Windows NT\\CurrentVersion',

        # Authentication and Logon
        'Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI',

        # Persistence Mechanisms (Autoruns)
        'Microsoft\\Windows\\CurrentVersion\\Run',
        'Microsoft\\Windows\\CurrentVersion\\RunOnce',
        'Microsoft\\Windows\\CurrentVersion\\RunServices',
        'Microsoft\\Windows\\CurrentVersion\\RunServicesOnce',
        'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
        'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce',

        # Network Information
        'Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles',
        'Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed',
        'Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged',

        # Time Zone Information
        'Microsoft\\Windows NT\\CurrentVersion\\TimeZoneInformation',

        # Application Execution
        'Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store',

        # Installed Applications
        'Microsoft\\Windows\\CurrentVersion\\Uninstall',
        'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall',

        # Services
        'Microsoft\\Windows NT\\CurrentVersion\\Svchost',

        # USB Devices
        'Microsoft\\Windows Portable Devices\\Devices',
        'Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt',
    ],

    'SYSTEM': [
        # Computer Name
        'ControlSet001\\Control\\ComputerName\\ComputerName',
        'CurrentControlSet\\Control\\ComputerName\\ComputerName',

        # Network Interfaces
        'ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces',
        'CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces',

        # USB Storage Devices
        'ControlSet001\\Enum\\USBSTOR',
        'CurrentControlSet\\Enum\\USBSTOR',
        'ControlSet001\\Enum\\USB',
        'CurrentControlSet\\Enum\\USB',

        # System Boot Information
        'ControlSet001\\Control\\Session Manager',
        'CurrentControlSet\\Control\\Session Manager',

        # Time Zone
        'ControlSet001\\Control\\TimeZoneInformation',
        'CurrentControlSet\\Control\\TimeZoneInformation',

        # Windows Services
        'ControlSet001\\Services',
        'CurrentControlSet\\Services',

        # Mounted Devices
        'MountedDevices',

        # System Boot Configuration
        'Select',
    ],

    'SAM': [
        # Local User Accounts
        'SAM\\Domains\\Account\\Users',
        'SAM\\Domains\\Account\\Users\\Names',
    ],

    'NTUSER': [
        # Recent Documents
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs',

        # Typed Paths (Explorer Address Bar)
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths',

        # Run MRU (Most Recently Used)
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU',

        # User Assist (Application Execution)
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist',

        # Word Wheel Query (Search Terms)
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery',

        # Mounted Devices (User-specific)
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2',

        # Shell Bags (Folder Access)
        'Software\\Microsoft\\Windows\\Shell\\BagMRU',
        'Software\\Microsoft\\Windows\\Shell\\Bags',
        'Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU',
        'Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags',

        # Office Recent Files
        'Software\\Microsoft\\Office\\16.0\\Word\\File MRU',
        'Software\\Microsoft\\Office\\16.0\\Excel\\File MRU',
        'Software\\Microsoft\\Office\\16.0\\PowerPoint\\File MRU',
        'Software\\Microsoft\\Office\\15.0\\Word\\File MRU',
        'Software\\Microsoft\\Office\\15.0\\Excel\\File MRU',

        # Map Network Drives
        'Network',

        # Terminal Server Client (RDP Connections)
        'Software\\Microsoft\\Terminal Server Client\\Servers',
        'Software\\Microsoft\\Terminal Server Client\\Default',
    ],

    'SECURITY': [
        # Security Policy
        'Policy\\Secrets',
        'Policy\\PolAdtEv',
    ],

    'USRCLASS': [
        # User Classes and Shell Bags
        'Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU',
        'Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags',
    ]
}

# Dictionary mapping registry key paths to specific values of forensic interest
forensic_values = {
    # System Version and Installation
    'Microsoft\\Windows NT\\CurrentVersion': [
        'InstallDate',          # OS installation timestamp
        'ProductName',          # Windows version name
        'CurrentBuild',         # Build number
        'CurrentBuildNumber',   # Alternative build number location
        'DisplayVersion',       # Display version (e.g., 21H2)
        'RegisteredOwner',      # Registered owner name
        'RegisteredOrganization',  # Registered organization
        'InstallTime',          # Installation time (if available)
        'SystemRoot',           # Windows directory path
        'PathName',             # Installation path
    ],

    # Last Logon Information
    'Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI': [
        'LastLoggedOnUser',     # Last logged on user (domain\\username)
        'SelectedUserSID',      # SID of selected user
        'LastLoggedOnSAMUser',  # Last SAM user
        'LastLoggedOnUserSID',  # SID of last logged on user
        'LastLoggedOnDisplayName',  # Display name of last user
    ],

    # Autorun Locations - All values are significant
    'Microsoft\\Windows\\CurrentVersion\\Run': ['all'],
    'Microsoft\\Windows\\CurrentVersion\\RunOnce': ['all'],
    'Microsoft\\Windows\\CurrentVersion\\RunServices': ['all'],
    'Microsoft\\Windows\\CurrentVersion\\RunServicesOnce': ['all'],
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run': ['all'],
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce': ['all'],

    # Network Profiles - All values are significant
    'Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles': ['all'],
    'Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Managed': ['all'],
    'Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged': ['all'],

    # Time Zone
    'Microsoft\\Windows NT\\CurrentVersion\\TimeZoneInformation': [
        'TimeZoneKeyName',      # Current time zone
        'ActiveTimeBias',       # Active time bias
    ],

    # Computer Name
    'ControlSet001\\Control\\ComputerName\\ComputerName': [
        'ComputerName',         # System computer name
    ],
    'CurrentControlSet\\Control\\ComputerName\\ComputerName': [
        'ComputerName',
    ],

    # USB Storage - All subkeys are significant
    'ControlSet001\\Enum\\USBSTOR': ['all'],
    'CurrentControlSet\\Enum\\USBSTOR': ['all'],
    'ControlSet001\\Enum\\USB': ['all'],
    'CurrentControlSet\\Enum\\USB': ['all'],

    # Recent Documents - All values are significant
    'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs': ['all'],
    'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths': ['all'],
    'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU': ['all'],
    'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist': ['all'],
    'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery': ['all'],
    'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2': ['all'],

    # Shell Bags
    'Software\\Microsoft\\Windows\\Shell\\BagMRU': ['all'],
    'Software\\Microsoft\\Windows\\Shell\\Bags': ['all'],

    # Terminal Server Client (RDP)
    'Software\\Microsoft\\Terminal Server Client\\Servers': ['all'],
    'Software\\Microsoft\\Terminal Server Client\\Default': ['all'],

    # System Boot
    'Select': [
        'Current',              # Current control set
        'Default',              # Default control set
        'Failed',               # Failed control set
        'LastKnownGood',        # Last known good control set
    ],

    # Additional Autoruns
    'Microsoft\\Windows\\CurrentVersion\\RunServices': ['all'],
    'Microsoft\\Windows\\CurrentVersion\\RunServicesOnce': ['all'],
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run': ['all'],
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce': ['all'],

    # Application Compatibility
    'Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store': ['all'],

    # Installed Applications
    'Microsoft\\Windows\\CurrentVersion\\Uninstall': ['all'],
    'Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall': ['all'],

    # USB Devices (SOFTWARE hive)
    'Microsoft\\Windows Portable Devices\\Devices': ['all'],
    'Microsoft\\Windows NT\\CurrentVersion\\EMDMgmt': ['all'],

    # Services
    'Microsoft\\Windows NT\\CurrentVersion\\Svchost': ['all'],

    # SYSTEM hive values
    'ControlSet001\\Control\\ComputerName\\ComputerName': ['ComputerName'],
    'CurrentControlSet\\Control\\ComputerName\\ComputerName': ['ComputerName'],

    # Network Interfaces
    'ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces': ['all'],
    'CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces': ['all'],

    # USB Storage
    'ControlSet001\\Enum\\USBSTOR': ['all'],
    'CurrentControlSet\\Enum\\USBSTOR': ['all'],
    'ControlSet001\\Enum\\USB': ['all'],
    'CurrentControlSet\\Enum\\USB': ['all'],

    # Session Manager
    'ControlSet001\\Control\\Session Manager': ['all'],
    'CurrentControlSet\\Control\\Session Manager': ['all'],

    # Time Zone (SYSTEM)
    'ControlSet001\\Control\\TimeZoneInformation': [
        'TimeZoneKeyName',
        'ActiveTimeBias',
        'Bias',
    ],
    'CurrentControlSet\\Control\\TimeZoneInformation': [
        'TimeZoneKeyName',
        'ActiveTimeBias',
        'Bias',
    ],

    # Services
    'ControlSet001\\Services': ['all'],
    'CurrentControlSet\\Services': ['all'],

    # Mounted Devices
    'MountedDevices': ['all'],

    # SAM hive
    'SAM\\Domains\\Account\\Users': ['all'],
    'SAM\\Domains\\Account\\Users\\Names': ['all'],

    # Shell Bags (additional locations)
    'Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU': ['all'],
    'Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags': ['all'],

    # Office MRU
    'Software\\Microsoft\\Office\\16.0\\Word\\File MRU': ['all'],
    'Software\\Microsoft\\Office\\16.0\\Excel\\File MRU': ['all'],
    'Software\\Microsoft\\Office\\16.0\\PowerPoint\\File MRU': ['all'],
    'Software\\Microsoft\\Office\\15.0\\Word\\File MRU': ['all'],
    'Software\\Microsoft\\Office\\15.0\\Excel\\File MRU': ['all'],

    # Network drives
    'Network': ['all'],

    # USRCLASS hive
    'Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU': ['all'],
    'Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags': ['all'],

    # SECURITY hive
    'Policy\\Secrets': ['all'],
    'Policy\\PolAdtEv': ['all'],
}

# Categorized registry artifacts for easier reference
FORENSIC_CATEGORIES = {
    'system_info': [
        'Microsoft\\Windows NT\\CurrentVersion',
    ],
    'user_activity': [
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs',
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist',
        'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery',
    ],
    'persistence': [
        'Microsoft\\Windows\\CurrentVersion\\Run',
        'Microsoft\\Windows\\CurrentVersion\\RunOnce',
    ],
    'network': [
        'Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles',
    ],
    'usb_devices': [
        'ControlSet001\\Enum\\USBSTOR',
        'CurrentControlSet\\Enum\\USBSTOR',
    ],
}