"""
Forensic Toolbox - Digital Forensics Artifacts Parser

A comprehensive toolbox for parsing forensic artifacts including:
- Registry hives (SOFTWARE, SYSTEM, SAM, NTUSER, SECURITY, USRCLASS)
- Prefetch files (.pf)
- Windows shortcuts (.lnk)
- Windows Event Logs (.evtx)
- Memory dumps (via Volatility 3)
"""

__version__ = "1.0.0"
__author__ = "Prof-GP"
__email__ = "practical4n6@gmail.com"

from .toolbox_registry import ToolboxRegistry
from .toolbox_prefetch import ToolboxPrefetch
from .toolbox_lnk import ToolboxLnk
from .toolbox_evtx import ToolboxEvtx

# Volatility is optional
try:
    from .toolbox_volatility import ToolboxVolatility
    __all__ = [
        'ToolboxRegistry',
        'ToolboxPrefetch',
        'ToolboxLnk',
        'ToolboxEvtx',
        'ToolboxVolatility'
    ]
except ImportError:
    __all__ = [
        'ToolboxRegistry',
        'ToolboxPrefetch',
        'ToolboxLnk',
        'ToolboxEvtx'
    ]