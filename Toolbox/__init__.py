"""
Forensic Toolbox - Windows Forensic Artifacts Parser

A comprehensive toolbox for parsing Windows forensic artifacts including:
- Registry hives (SOFTWARE, SYSTEM, SAM, NTUSER, SECURITY, USRCLASS)
- Prefetch files (.pf)
- Windows shortcuts (.lnk)
"""

__version__ = "1.0.0"
__author__ = "ProgGP"
__email__ = "practical4n6@gmail.com"

from .toolbox_registry import ToolboxRegistry
from .toolbox_prefetch import ToolboxPrefetch
from .toolbox_lnk import ToolboxLnk
from .toolbox_evtx import ToolboxEvtx

__all__ = [
    'ToolboxRegistry',
    'ToolboxPrefetch',
    'ToolboxLnk',
    'ToolboxEvtx'
]