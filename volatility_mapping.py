"""
Volatility 3 Plugin Mappings for Digital Forensics
Contains forensically relevant plugins organized by OS type and category.
"""

# Forensically relevant plugins organized by OS and category
FORENSIC_PLUGINS = {
    'Windows': {
        'processes': [
            'windows.pslist.PsList',
            'windows.pstree.PsTree',
            'windows.dlllist.DllList',
            'windows.cmdline.CmdLine',
            'windows.envars.Envars',
        ],
        'processes_scan': [
            'windows.psscan.PsScan',  # SLOW: Scans entire memory
            'windows.handles.Handles',  # Can be slow with many processes
        ],
        'network': [
            'windows.netscan.NetScan',
            'windows.netstat.NetStat',
        ],
        'registry': [
            'windows.registry.hivelist.HiveList',
            'windows.registry.userassist.UserAssist',
            'windows.registry.printkey.PrintKey',
        ],
        'files': [
            'windows.filescan.FileScan',
        ],
        'malware_indicators': [
            'windows.malfind.Malfind',
            'windows.modules.Modules',
            'windows.ssdt.SSDT',
            'windows.callbacks.Callbacks',
        ],
        'malware_scan': [
            'windows.vadinfo.VadInfo',  # Can be slow
            'windows.modscan.ModScan',  # SLOW: Scans entire memory
            'windows.driverscan.DriverScan',  # SLOW: Scans entire memory
        ],
        'system_info': [
            'windows.info.Info',
            'windows.svcscan.SvcScan',
            'windows.getservicesids.GetServiceSIDs',
        ],
    },
    'Linux': {
        'processes': [
            'linux.pslist.PsList',
            'linux.pstree.PsTree',
            'linux.bash.Bash',
        ],
        'network': [
            'linux.sockstat.Sockstat',
        ],
        'files': [
            'linux.lsof.Lsof',
            'linux.mount.Mount',
        ],
        'system_info': [
            'linux.info.Info',
        ],
    },
    'Mac': {
        'processes': [
            'mac.pslist.PsList',
            'mac.pstree.PsTree',
        ],
        'network': [
            'mac.netstat.Netstat',
        ],
        'system_info': [
            'mac.info.Info',
        ],
    }
}

# Plugin descriptions for user-friendly output
PLUGIN_DESCRIPTIONS = {
    # Windows plugins
    'windows.pslist.PsList': 'List active processes (FAST)',
    'windows.pstree.PsTree': 'Process tree hierarchy (FAST)',
    'windows.psscan.PsScan': 'Scan for hidden/terminated processes (VERY SLOW - scans entire memory)',
    'windows.dlllist.DllList': 'List loaded DLLs per process',
    'windows.handles.Handles': 'List open handles per process (can be slow)',
    'windows.cmdline.CmdLine': 'Display process command-line arguments (FAST)',
    'windows.envars.Envars': 'Display process environment variables',
    'windows.netscan.NetScan': 'Scan for network connections and sockets',
    'windows.netstat.NetStat': 'Active network connections (FAST)',
    'windows.registry.hivelist.HiveList': 'List registry hive locations in memory',
    'windows.registry.userassist.UserAssist': 'Extract UserAssist registry data',
    'windows.registry.printkey.PrintKey': 'Print registry key values',
    'windows.filescan.FileScan': 'Scan for file objects in memory (SLOW)',
    'windows.malfind.Malfind': 'Detect hidden/injected code and memory anomalies',
    'windows.vadinfo.VadInfo': 'Display Virtual Address Descriptor (VAD) information (can be slow)',
    'windows.modules.Modules': 'List loaded kernel modules (FAST)',
    'windows.modscan.ModScan': 'Scan for unlinked kernel modules (VERY SLOW - scans entire memory)',
    'windows.driverscan.DriverScan': 'Scan for driver objects (VERY SLOW - scans entire memory)',
    'windows.ssdt.SSDT': 'Display System Service Descriptor Table (FAST)',
    'windows.callbacks.Callbacks': 'List kernel callbacks (FAST)',
    'windows.info.Info': 'Display OS and kernel information (FAST)',
    'windows.svcscan.SvcScan': 'Scan for Windows services',
    'windows.getservicesids.GetServiceSIDs': 'Get service SIDs',

    # Linux plugins
    'linux.pslist.PsList': 'List active processes',
    'linux.pstree.PsTree': 'Process tree hierarchy',
    'linux.bash.Bash': 'Extract bash command history',
    'linux.sockstat.Sockstat': 'List open sockets',
    'linux.lsof.Lsof': 'List open files per process',
    'linux.mount.Mount': 'Display mounted filesystems',
    'linux.info.Info': 'Display OS and kernel information',

    # Mac plugins
    'mac.pslist.PsList': 'List active processes',
    'mac.pstree.PsTree': 'Process tree hierarchy',
    'mac.netstat.Netstat': 'List network connections',
    'mac.info.Info': 'Display OS and kernel information',
}

# Priority plugins to run first (quick analysis)
PRIORITY_PLUGINS = {
    'Windows': [
        'windows.info.Info',
        'windows.pslist.PsList',
        'windows.netscan.NetScan',
        'windows.cmdline.CmdLine',
    ],
    'Linux': [
        'linux.info.Info',
        'linux.pslist.PsList',
        'linux.sockstat.Sockstat',
    ],
    'Mac': [
        'mac.info.Info',
        'mac.pslist.PsList',
        'mac.netstat.Netstat',
    ]
}


def get_plugin_description(plugin_name: str) -> str:
    """
    Get a human-readable description for a plugin.

    Args:
        plugin_name: Full plugin path (e.g., 'windows.pslist.PsList')

    Returns:
        Description string or 'No description available'
    """
    return PLUGIN_DESCRIPTIONS.get(plugin_name, 'No description available')


def get_all_plugins_for_os(os_type: str) -> list:
    """
    Get all forensically relevant plugins for a specific OS.

    Args:
        os_type: OS type ('Windows', 'Linux', 'Mac')

    Returns:
        List of plugin names
    """
    if os_type not in FORENSIC_PLUGINS:
        return []

    all_plugins = []
    for category, plugins in FORENSIC_PLUGINS[os_type].items():
        all_plugins.extend(plugins)

    return all_plugins


def get_plugins_by_category(os_type: str, categories: list) -> list:
    """
    Get plugins filtered by specific categories.

    Args:
        os_type: OS type ('Windows', 'Linux', 'Mac')
        categories: List of category names (e.g., ['processes', 'network'])

    Returns:
        List of plugin names
    """
    if os_type not in FORENSIC_PLUGINS:
        return []

    plugins = []
    for category in categories:
        if category in FORENSIC_PLUGINS[os_type]:
            plugins.extend(FORENSIC_PLUGINS[os_type][category])

    return plugins


def get_priority_plugins(os_type: str) -> list:
    """
    Get priority plugins for quick analysis.

    Args:
        os_type: OS type ('Windows', 'Linux', 'Mac')

    Returns:
        List of priority plugin names
    """
    return PRIORITY_PLUGINS.get(os_type, [])
