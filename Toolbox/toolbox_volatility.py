"""
Volatility 3 Memory Forensics Integration for Forensic Toolbox
Provides automated memory dump analysis using Volatility 3 Python module.
"""

import os
import json
import csv
import time
import io
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime

from volatility_mapping import (
    get_all_plugins_for_os,
    get_plugins_by_category,
    get_priority_plugins,
    get_plugin_description,
    FORENSIC_PLUGINS
)

# Check for Volatility 3 Python module
VOLATILITY_AVAILABLE = False
IMPORT_ERROR = None

try:
    from volatility3.framework import contexts, plugins, constants
    from volatility3.framework.configuration import requirements
    from volatility3.framework import automagic
    from volatility3.cli.text_renderer import QuickTextRenderer, JsonRenderer, CSVRenderer
    try:
        from volatility3.cli.text_renderer import MarkdownRenderer
    except ImportError:
        MarkdownRenderer = None
    import volatility3.plugins
    VOLATILITY_AVAILABLE = True
except ImportError as e:
    IMPORT_ERROR = str(e)
    # Set placeholders for type hints
    QuickTextRenderer = None
    JsonRenderer = None
    CSVRenderer = None
    MarkdownRenderer = None
except Exception as e:
    IMPORT_ERROR = f"Unexpected error: {str(e)}"
    QuickTextRenderer = None
    JsonRenderer = None
    CSVRenderer = None
    MarkdownRenderer = None


class ToolboxVolatility:
    """
    Volatility 3 Memory Forensics Analyzer

    Automatically detects OS type and runs forensically relevant plugins
    on memory dump files, outputting results to separate files per plugin.

    Attributes:
        memory_image: Path to memory dump file
        output_dir: Directory for plugin output files
        os_type: Detected or specified OS type ('Windows', 'Linux', 'Mac')
        context: Volatility 3 context object
        plugins_run: List of successfully executed plugins
        plugins_failed: List of failed plugins with error details
        results: Dictionary storing metadata per plugin
        timeout: Timeout in seconds for each plugin
    """

    def __init__(self, memory_image_path: str, output_dir: Optional[str] = None,
                 os_type: Optional[str] = None, timeout: int = 300):
        """
        Initialize Volatility analyzer.

        Args:
            memory_image_path: Path to memory dump file
            output_dir: Output directory (default: {image_name}_volatility_output)
            os_type: Force specific OS type ('Windows', 'Linux', 'Mac')
            timeout: Timeout in seconds for each plugin (default: 300)

        Raises:
            FileNotFoundError: If memory image doesn't exist
            ImportError: If Volatility 3 is not installed
        """
        if not VOLATILITY_AVAILABLE:
            error_msg = "Volatility 3 Python module not found.\n"
            if IMPORT_ERROR:
                error_msg += f"Import error: {IMPORT_ERROR}\n"
            error_msg += "Install with: pip install volatility3"
            raise ImportError(error_msg)

        if not os.path.exists(memory_image_path):
            raise FileNotFoundError(f"Memory image not found: {memory_image_path}")

        self.memory_image = os.path.abspath(memory_image_path)
        self.os_type = os_type
        self.timeout = timeout

        # Set up output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            image_name = Path(memory_image_path).stem
            self.output_dir = Path(f"{image_name}_volatility_output")

        self.output_dir.mkdir(exist_ok=True)

        # Check file size
        file_size = os.path.getsize(self.memory_image)
        self.file_size_gb = file_size / (1024**3)

        # Initialize tracking
        self.plugins_run = []
        self.plugins_failed = []
        self.results = {}
        self.analysis_start_time = None
        self.analysis_end_time = None
        self.os_info = {}

    def detect_os(self) -> str:
        """
        Auto-detect OS type using info plugins.

        Strategy:
            1. Try windows.info.Info - if succeeds, it's Windows
            2. Try linux.info.Info - if succeeds, it's Linux
            3. Try mac.info.Info - if succeeds, it's Mac
            4. If all fail, return 'Unknown'

        Returns:
            OS type string ('Windows', 'Linux', 'Mac', or 'Unknown')
        """
        if self.os_type:
            return self.os_type

        print("[*] Detecting operating system...")

        # Try each OS-specific info plugin (with fallback plugins)
        os_detection_map = {
            'Windows': ['windows.info.Info', 'windows.pslist.PsList'],
            'Linux': ['linux.pslist.PsList', 'linux.bash.Bash'],
            'Mac': ['mac.pslist.PsList', 'mac.netstat.Netstat']
        }

        for os_name, plugin_list in os_detection_map.items():
            print(f"    [*] Trying {os_name}...")

            # Try each plugin for this OS
            last_error = None
            for plugin_name in plugin_list:
                try:
                    # Try to run the plugin
                    result = self._execute_plugin_internal(plugin_name, detect_mode=False)

                    # If it succeeded, we found the OS
                    if result and result.get('success'):
                        print(f"    [+] Detected: {os_name} (via {plugin_name})")
                        self.os_type = os_name
                        return os_name
                    elif result and result.get('error'):
                        last_error = result.get('error')
                        print(f"        [-] {plugin_name}: {last_error[:150]}")

                except Exception as e:
                    last_error = str(e)
                    print(f"        [-] {plugin_name}: Exception: {str(e)[:150]}")
                    continue

            # If all plugins for this OS failed, show last error
            if last_error:
                print(f"    [-] {os_name}: Failed - {last_error[:100]}")

        # If all fail, return Unknown
        print("    [!] Could not auto-detect OS")
        self.os_type = 'Unknown'
        return 'Unknown'

    def _execute_plugin_internal(self, plugin_name: str, detect_mode: bool = False,
                                 output_format: str = 'text') -> Dict:
        """
        Execute a Volatility plugin using Python API.

        Args:
            plugin_name: Plugin name (e.g., 'windows.pslist.PsList')
            detect_mode: If True, suppress output (for OS detection)
            output_format: Output format ('text' or 'json')

        Returns:
            Dictionary with execution results and rendered output
        """
        try:
            # Import the plugin dynamically
            import importlib

            # Parse plugin name: windows.pslist.PsList -> volatility3.plugins.windows.pslist
            parts = plugin_name.split('.')
            if len(parts) < 2:
                return {'error': f'Invalid plugin name format: {plugin_name}'}

            class_name = parts[-1]
            module_path = '.'.join(parts[:-1])
            full_module_path = f'volatility3.plugins.{module_path}'

            try:
                plugin_module = importlib.import_module(full_module_path)
                plugin_class = getattr(plugin_module, class_name)
            except (ImportError, AttributeError) as e:
                return {'error': f'Failed to load plugin {plugin_name}: {str(e)}'}

            # Create context
            ctx = contexts.Context()

            # Set memory image location - convert to proper URI format
            normalized_path = os.path.abspath(self.memory_image).replace('\\', '/')
            if os.name == 'nt':  # Windows
                # Windows needs file:/// (three slashes)
                file_uri = f"file:///{normalized_path}"
            else:
                # Unix needs file:// (two slashes)
                file_uri = f"file://{normalized_path}"

            ctx.config['automagic.LayerStacker.single_location'] = file_uri

            # Get automagic
            try:
                available_automagics = automagic.available(ctx)
                automagics = automagic.choose_automagic(available_automagics, plugin_class)
            except Exception as e:
                return {'error': f'Automagic failed: {str(e)}'}

            # Construct the plugin
            try:
                plugin = plugins.construct_plugin(
                    ctx,
                    automagics,
                    plugin_class,
                    'plugins',
                    None,  # progress_callback
                    None   # file_consumer
                )
            except Exception as e:
                return {'error': f'Plugin construction failed: {str(e)}'}

            # Run the plugin to get TreeGrid
            try:
                tree_grid = plugin.run()
            except Exception as e:
                return {'error': f'Plugin execution failed: {str(e)}'}

            if tree_grid is None:
                return {'error': 'Plugin returned None (incompatible OS or corrupted dump)'}

            # Choose renderer based on output format and render the tree_grid
            # Note: Renderers print to stdout, so we need to capture it
            old_stdout = sys.stdout
            sys.stdout = io.StringIO()

            try:
                if output_format == 'json':
                    renderer = JsonRenderer()
                    renderer.render(tree_grid)
                elif output_format == 'csv':
                    renderer = CSVRenderer()
                    renderer.render(tree_grid)
                elif output_format == 'markdown':
                    if MarkdownRenderer:
                        renderer = MarkdownRenderer()
                        renderer.render(tree_grid)
                    else:
                        # Fall back to text if markdown not available
                        renderer = QuickTextRenderer()
                        renderer.render(tree_grid)
                        output_format = 'text'
                else:
                    # Default to QuickTextRenderer for text output
                    renderer = QuickTextRenderer()
                    renderer.render(tree_grid)

                # Get the captured output
                rendered_output = sys.stdout.getvalue()
            finally:
                # Restore stdout
                sys.stdout = old_stdout

            if not rendered_output or not rendered_output.strip():
                return {'success': True, 'output': '', 'rows': [], 'format': output_format}

            return {
                'success': True,
                'output': rendered_output,
                'rows': rendered_output.splitlines() if output_format == 'text' else [],
                'format': output_format
            }

        except Exception as e:
            error_msg = str(e)
            if not detect_mode:
                print(f"        [!] Plugin error: {error_msg}")
            return {'error': error_msg}

    def _render_to_json(self, data: List[Dict], output_file: Path) -> bool:
        """
        Render data to JSON format.

        Args:
            data: List of dictionaries to render
            output_file: Output file path

        Returns:
            True if successful
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            print(f"        [!] JSON write error: {e}")
            return False

    def _render_to_csv(self, data: List[Dict], output_file: Path) -> bool:
        """
        Render data to CSV format.

        Args:
            data: List of dictionaries to render
            output_file: Output file path

        Returns:
            True if successful
        """
        try:
            if not data:
                return False

            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
            return True
        except Exception as e:
            print(f"        [!] CSV write error: {e}")
            return False

    def _render_to_text(self, data: List[Dict], output_file: Path) -> bool:
        """
        Render data to text format.

        Args:
            data: List of dictionaries to render
            output_file: Output file path

        Returns:
            True if successful
        """
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                if not data:
                    f.write("No data\n")
                    return True

                # Write column headers
                headers = list(data[0].keys())
                col_widths = [max(len(str(h)), 15) for h in headers]

                # Adjust column widths based on data
                for row in data:
                    for idx, key in enumerate(headers):
                        val_len = len(str(row.get(key, '')))
                        col_widths[idx] = max(col_widths[idx], val_len)

                # Limit column widths
                col_widths = [min(w, 50) for w in col_widths]

                # Write header
                header_line = ' | '.join(h.ljust(col_widths[idx]) for idx, h in enumerate(headers))
                f.write(header_line + '\n')
                f.write('-' * len(header_line) + '\n')

                # Write data
                for row in data:
                    values = [str(row.get(k, ''))[:col_widths[idx]].ljust(col_widths[idx])
                             for idx, k in enumerate(headers)]
                    f.write(' | '.join(values) + '\n')

            return True
        except Exception as e:
            print(f"        [!] Text write error: {e}")
            return False

    def run_plugin(self, plugin_name: str, output_format: str = 'text') -> bool:
        """
        Execute a single Volatility plugin.

        Args:
            plugin_name: Full plugin path (e.g., 'windows.pslist.PsList')
            output_format: Output format ('text', 'json', 'csv', 'markdown')

        Returns:
            True if successful, False otherwise
        """
        try:
            # Execute plugin with timeout
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._execute_plugin_internal, plugin_name, False, output_format)
                try:
                    result = future.result(timeout=self.timeout)
                except FuturesTimeoutError:
                    print(f"        [!] Plugin timed out after {self.timeout}s")
                    self.plugins_failed.append({
                        'plugin': plugin_name,
                        'error': f'Timeout after {self.timeout}s',
                        'timestamp': datetime.now().isoformat()
                    })
                    return False

            if result.get('error'):
                self.plugins_failed.append({
                    'plugin': plugin_name,
                    'error': result['error'],
                    'timestamp': datetime.now().isoformat()
                })
                return False

            # Determine file extension based on format
            format_ext = result.get('format', 'text')
            extension_map = {
                'json': 'json',
                'csv': 'csv',
                'markdown': 'md',
                'text': 'txt'
            }
            file_ext = extension_map.get(format_ext, 'txt')

            # Save output to file
            safe_name = plugin_name.replace('.', '_')
            output_file = self.output_dir / f"{safe_name}.{file_ext}"

            output = result.get('output', '')
            rows = result.get('rows', [])

            # Write the rendered output directly
            if output:
                row_count = len(rows) if rows else output.count('\n')
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(output)
                success = True
            # No data
            else:
                print(f"        [!] Warning: Plugin returned no data")
                row_count = 0
                with open(output_file, 'w', encoding='utf-8') as f:
                    if format_ext == 'json':
                        f.write('[]')
                    elif format_ext == 'csv':
                        f.write('')  # Empty CSV
                    else:
                        f.write('No data\n')
                success = True

            if success:
                self.plugins_run.append(plugin_name)
                self.results[plugin_name] = {
                    'output_file': str(output_file),
                    'row_count': row_count,
                    'timestamp': datetime.now().isoformat()
                }
                return True
            else:
                self.plugins_failed.append({
                    'plugin': plugin_name,
                    'error': 'Failed to write output',
                    'timestamp': datetime.now().isoformat()
                })
                return False

        except Exception as e:
            self.plugins_failed.append({
                'plugin': plugin_name,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
            return False

    def run_specific_plugins(self, plugin_list: List[str],
                           output_format: str = 'text') -> Dict:
        """
        Run a specific list of plugins.

        Args:
            plugin_list: List of plugin names to run
            output_format: Output format for all plugins

        Returns:
            Summary dictionary with execution statistics
        """
        print(f"\n[*] Running {len(plugin_list)} specified plugins...")

        self.analysis_start_time = time.time()

        for idx, plugin_name in enumerate(plugin_list, 1):
            description = get_plugin_description(plugin_name)
            print(f"\n[{idx}/{len(plugin_list)}] {plugin_name}")
            print(f"    {description}")

            start_time = time.time()
            success = self.run_plugin(plugin_name, output_format)
            elapsed = time.time() - start_time

            if success:
                print(f"    [+] Completed in {elapsed:.2f}s")
            else:
                print(f"    [!] Failed after {elapsed:.2f}s")

        self.analysis_end_time = time.time()

        return self._generate_summary()

    def run_priority_analysis(self, output_format: str = 'text') -> Dict:
        """
        Run priority plugins for quick analysis.

        Args:
            output_format: Output format for all plugins

        Returns:
            Summary dictionary with execution statistics
        """
        if self.os_type == 'Unknown':
            self.detect_os()

        if self.os_type == 'Unknown':
            print("[!] Cannot run priority analysis without detecting OS")
            return self._generate_summary()

        priority_plugins = get_priority_plugins(self.os_type)

        if not priority_plugins:
            print(f"[!] No priority plugins defined for {self.os_type}")
            return self._generate_summary()

        print(f"[*] Running priority analysis for {self.os_type}...")
        return self.run_specific_plugins(priority_plugins, output_format)

    def run_forensic_analysis(self, categories: Optional[List[str]] = None,
                            plugin_list: Optional[List[str]] = None,
                            output_format: str = 'text') -> Dict:
        """
        Run comprehensive forensic analysis.

        Args:
            categories: Specific categories to run (e.g., ['processes', 'network'])
            plugin_list: Override with specific plugin list
            output_format: Output format for all plugins

        Returns:
            Summary dictionary with execution statistics
        """
        # Detect OS if needed
        if self.os_type == 'Unknown' or not self.os_type:
            self.detect_os()

        if self.os_type == 'Unknown':
            print("[!] Cannot run forensic analysis without detecting OS")
            return self._generate_summary()

        # Determine which plugins to run
        if plugin_list:
            selected_plugins = plugin_list
        elif categories:
            selected_plugins = get_plugins_by_category(self.os_type, categories)
        else:
            selected_plugins = get_all_plugins_for_os(self.os_type)

        if not selected_plugins:
            print("[!] No plugins selected for analysis")
            return self._generate_summary()

        # Display analysis plan
        print(f"\n[*] Forensic Analysis Plan")
        print(f"    Memory Image: {self.memory_image}")
        print(f"    Image Size: {self.file_size_gb:.2f} GB")
        print(f"    OS Type: {self.os_type}")
        print(f"    Plugins to Run: {len(selected_plugins)}")
        print(f"    Output Directory: {self.output_dir}")
        print(f"    Output Format: {output_format}")
        print(f"    Plugin Timeout: {self.timeout}s")

        if self.file_size_gb > 8:
            print(f"\n[!] Warning: Large memory image detected")
            print(f"    Analysis may take significant time and resources")

        # Run plugins
        return self.run_specific_plugins(selected_plugins, output_format)

    def _generate_summary(self) -> Dict:
        """
        Generate analysis summary.

        Returns:
            Dictionary with analysis statistics
        """
        total_plugins = len(self.plugins_run) + len(self.plugins_failed)

        summary = {
            'total_plugins': total_plugins,
            'successful': len(self.plugins_run),
            'failed': len(self.plugins_failed),
            'success_rate': (len(self.plugins_run) / total_plugins * 100) if total_plugins > 0 else 0
        }

        if self.analysis_start_time and self.analysis_end_time:
            summary['duration_seconds'] = self.analysis_end_time - self.analysis_start_time

        return summary

    def print_summary(self):
        """Print analysis summary to console."""
        print("\n" + "=" * 70)
        print("VOLATILITY ANALYSIS SUMMARY")
        print("=" * 70)

        print(f"\nMemory Image: {self.memory_image}")
        print(f"Image Size: {self.file_size_gb:.2f} GB")
        print(f"OS Detected: {self.os_type}")
        print(f"Output Directory: {self.output_dir}")

        if self.os_info:
            print(f"\nOS Information:")
            for key, value in list(self.os_info.items())[:5]:
                print(f"  {key}: {value}")

        print(f"\nPlugins Executed: {len(self.plugins_run) + len(self.plugins_failed)}")
        print(f"  Successful: {len(self.plugins_run)}")
        print(f"  Failed: {len(self.plugins_failed)}")

        if self.analysis_start_time and self.analysis_end_time:
            duration = self.analysis_end_time - self.analysis_start_time
            print(f"\nTotal Duration: {duration:.2f} seconds ({duration/60:.2f} minutes)")

        if self.plugins_run:
            print(f"\nSuccessful Plugins:")
            for plugin in self.plugins_run:
                result_info = self.results.get(plugin, {})
                row_count = result_info.get('row_count', 0)
                print(f"  [+] {plugin} ({row_count} rows)")

        if self.plugins_failed:
            print(f"\nFailed Plugins:")
            for failure in self.plugins_failed:
                print(f"  [!] {failure['plugin']}: {failure['error']}")

        print("\n" + "=" * 70)

    def export_summary(self, output_file: str):
        """
        Export analysis summary to JSON file.

        Args:
            output_file: Path to output JSON file
        """
        summary = {
            'analysis_metadata': {
                'memory_image': self.memory_image,
                'image_size_gb': self.file_size_gb,
                'analysis_timestamp': datetime.now().isoformat(),
                'output_directory': str(self.output_dir),
            },
            'os_detection': {
                'os_type': self.os_type,
                'os_info': self.os_info,
            },
            'execution_summary': {
                'total_plugins': len(self.plugins_run) + len(self.plugins_failed),
                'successful': len(self.plugins_run),
                'failed': len(self.plugins_failed),
                'plugins_run': self.plugins_run,
                'plugins_failed': self.plugins_failed,
            },
            'results': self.results,
        }

        if self.analysis_start_time and self.analysis_end_time:
            summary['execution_summary']['duration_seconds'] = \
                self.analysis_end_time - self.analysis_start_time

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, default=str)
            print(f"\n[+] Summary exported to: {output_file}")
        except Exception as e:
            print(f"\n[!] Failed to export summary: {e}")
