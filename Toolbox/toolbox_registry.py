"""
Digital Forensics Registry Analysis Tool
Provides methods to extract forensically significant data from Windows Registry hives.

Usage:
    from Toolbox.toolbox_registry import ToolboxRegistry

    reg = ToolboxRegistry('SOFTWARE', 'SOFTWARE')
    results = reg.valuable_keys()
"""

from Registry import Registry, RegistryParse
from registry_mapping import forensic_keys, forensic_values
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.WARNING)  # Changed from INFO to reduce noise
logger = logging.getLogger(__name__)


def convert_epoch(epoch):
    """
    Convert epoch timestamp to human-readable format.
    Handles both Unix epoch and Windows FILETIME formats.

    Args:
        epoch: Integer timestamp (Unix or Windows FILETIME) or other value

    Returns:
        str: Formatted datetime string or original value if conversion fails
    """
    try:
        if isinstance(epoch, int):
            # Try Unix epoch first (for values < 10000000000)
            if epoch < 10000000000:
                time = datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
                return time
            else:
                # Large values are likely Windows FILETIME
                time = RegistryParse.parse_windows_timestamp(epoch)
                return time
        else:
            return epoch
    except (OSError, ValueError, OverflowError) as e:
        # If Unix epoch fails, try Windows timestamp
        try:
            return RegistryParse.parse_windows_timestamp(epoch)
        except Exception:
            logger.warning(f"Could not convert timestamp: {epoch}")
            return epoch


def decode_binary_value(value):
    """
    Attempt to decode binary registry values.

    Args:
        value: Binary data from registry

    Returns:
        str or bytes: Decoded string if successful, original bytes otherwise
    """
    if isinstance(value, bytes):
        try:
            # Try UTF-16LE (common in Windows Registry)
            return RegistryParse.decode_utf16le(value)
        except Exception:
            try:
                # Try UTF-8
                return value.decode('utf-8').rstrip('\x00')
            except Exception:
                # Return hex representation for non-decodable binary
                return value.hex()
    return value


def rot13_decode(text):
    """
    Decode ROT13 encoded text (used in UserAssist).

    Args:
        text: ROT13 encoded string

    Returns:
        str: Decoded string
    """
    result = []
    for char in text:
        if 'a' <= char <= 'z':
            result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= char <= 'Z':
            result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(char)
    return ''.join(result)


def print_values(obj_list):
    """
    Extract all values from a registry key and format them.

    Args:
        obj_list: List of registry value objects

    Returns:
        dict: Dictionary mapping value names to tuples of (value, type)
    """
    list_values = {}

    try:
        for reg_object in obj_list:
            try:
                value = reg_object.value()
                value_type = reg_object.value_type_str()
                name = reg_object.name()

                # Handle binary values
                if isinstance(value, bytes):
                    decoded_value = decode_binary_value(value)
                    list_values[name] = (decoded_value, value_type)
                # Handle timestamps
                elif isinstance(value, int) and value > 1000000000:
                    converted_time = convert_epoch(value)
                    list_values[name] = (converted_time, value_type)
                else:
                    list_values[name] = (value, value_type)

            except Exception as e:
                logger.warning(f"Error processing value {reg_object.name()}: {e}")
                continue

    except (ValueError, AttributeError) as e:
        logger.error(f"Error in print_values: {e}")

    return list_values


class ToolboxRegistry:
    """
    Main class for extracting forensically significant registry data.

    Attributes:
        file (str): Path to registry hive file
        type (str): Type of registry hive (SOFTWARE, SYSTEM, SAM, NTUSER, SECURITY)
        reg (Registry): Registry object from python-registry library
    """

    def __init__(self, reg_file, reg_type):
        """
        Initialize the ToolboxRegistry with a registry file.

        Args:
            reg_file (str): Path to the registry hive file
            reg_type (str): Type of hive (SOFTWARE, SYSTEM, SAM, NTUSER, SECURITY, USRCLASS)

        Raises:
            Exception: If registry file cannot be opened
        """
        self.file = reg_file
        self.type = reg_type.upper()

        try:
            self.reg = Registry.Registry(reg_file)
            logger.info(f"Successfully opened registry hive: {reg_file}")
        except Exception as e:
            logger.error(f"Failed to open registry file {reg_file}: {e}")
            raise

    def valuable_keys(self):
        """
        Extract all forensically valuable keys and values from the registry hive.

        Returns:
            dict: Nested dictionary containing all extracted forensic data
                  Format: {key_path: {value_name: value_data}}
        """
        results = {}

        if self.type not in forensic_keys:
            logger.warning(f"Registry type {self.type} not found in forensic_keys")
            return results

        # Iterate through each forensically significant key for this hive type
        for key_path in forensic_keys[self.type]:
            try:
                key = self.reg.open(key_path)
                logger.info(f"Processing key: {key_path}")
                key_results = {}

                # Special handling for SAM user accounts
                if 'SAM\\Domains\\Account\\Users' in key_path:
                    key_results = self._process_sam_users(key, key_path)
                    # If special processing returned nothing, fall back to default
                    if not key_results:
                        key_results = print_values(key.values())
                        if not key_results and key.subkeys_number() > 0:
                            subkey_names = [subkey.name() for subkey in key.subkeys()]
                            key_results = {
                                '_subkeys_': subkey_names[:10],
                                '_total_subkeys_': key.subkeys_number()
                            }
                # Special handling for SECURITY hive
                elif self.type == 'SECURITY' and 'Policy' in key_path:
                    key_results = self._process_security_policy(key, key_path)
                    # If special processing returned nothing, fall back to default
                    if not key_results:
                        key_results = print_values(key.values())
                        if not key_results and key.subkeys_number() > 0:
                            subkey_names = [subkey.name() for subkey in key.subkeys()]
                            key_results = {
                                '_subkeys_': subkey_names[:10],
                                '_total_subkeys_': key.subkeys_number()
                            }
                # Special handling for UserAssist - enumerate subkeys and decode ROT13
                elif 'UserAssist' in key_path:
                    key_results = self._process_userassist(key)
                    # If special processing returned nothing, fall back to default
                    if not key_results:
                        key_results = print_values(key.values())
                        if not key_results and key.subkeys_number() > 0:
                            subkey_names = [subkey.name() for subkey in key.subkeys()]
                            key_results = {
                                '_subkeys_': subkey_names[:10],
                                '_total_subkeys_': key.subkeys_number()
                            }
                # Special handling for RecentDocs - enumerate subkeys
                elif 'RecentDocs' in key_path:
                    key_results = self._process_recentdocs(key)
                    if not key_results:
                        key_results = print_values(key.values())
                        if not key_results and key.subkeys_number() > 0:
                            subkey_names = [subkey.name() for subkey in key.subkeys()]
                            key_results = {
                                '_subkeys_': subkey_names[:10],
                                '_total_subkeys_': key.subkeys_number()
                            }
                # Special handling for MountPoints2 - enumerate devices
                elif 'MountPoints2' in key_path:
                    key_results = self._process_mountpoints(key)
                    if not key_results:
                        key_results = print_values(key.values())
                        if not key_results and key.subkeys_number() > 0:
                            subkey_names = [subkey.name() for subkey in key.subkeys()]
                            key_results = {
                                '_subkeys_': subkey_names[:10],
                                '_total_subkeys_': key.subkeys_number()
                            }
                # Special handling for TypedPaths
                elif 'TypedPaths' in key_path:
                    key_results = self._process_typedpaths(key)
                    if not key_results:
                        key_results = print_values(key.values())
                # Check if this key has specific values defined in forensic_values
                elif key_path in forensic_values:
                    for value_name in forensic_values[key_path]:
                        try:
                            # If 'all' is specified, extract all values from the key
                            if value_name == 'all':
                                key_results = print_values(key.values())
                                break  # No need to continue if we're getting all values

                            # Extract specific value
                            value_obj = key.value(value_name)
                            value = value_obj.value()

                            # Handle timestamps
                            if isinstance(value, int) and value > 1000000000:
                                value = convert_epoch(value)
                            # Handle binary data
                            elif isinstance(value, bytes):
                                value = decode_binary_value(value)

                            key_results[value_name] = value

                        except Registry.RegistryValueNotFoundException:
                            logger.debug(f"Value '{value_name}' not found in {key_path}")
                        except Exception as e:
                            logger.warning(f"Error extracting value '{value_name}' from {key_path}: {e}")
                else:
                    # Key exists but no specific values defined - extract all values
                    logger.info(f"No specific values defined for {key_path}, extracting all values")
                    key_results = print_values(key.values())

                # If no values found but key has subkeys, note the subkeys
                if not key_results and key.subkeys_number() > 0:
                    subkey_names = [subkey.name() for subkey in key.subkeys()]
                    key_results = {
                        '_subkeys_': subkey_names[:10],  # Limit to first 10 for readability
                        '_total_subkeys_': key.subkeys_number()
                    }
                    logger.info(f"Key {key_path} has {key.subkeys_number()} subkeys")

                if key_results:
                    results[key_path] = key_results

            except Registry.RegistryKeyNotFoundException:
                logger.debug(f"Key not found: {key_path}")
            except Exception as e:
                logger.error(f"Error processing key {key_path}: {e}")

        return results

    def get_subkeys(self, key_path):
        """
        Get all subkeys under a specified registry key path.
        Useful for enumerating USB devices, network profiles, etc.

        Args:
            key_path (str): Registry key path to enumerate

        Returns:
            list: List of subkey names
        """
        subkeys = []
        try:
            key = self.reg.open(key_path)
            subkeys = [subkey.name() for subkey in key.subkeys()]
            logger.info(f"Found {len(subkeys)} subkeys under {key_path}")
        except Registry.RegistryKeyNotFoundException:
            logger.warning(f"Key not found: {key_path}")
        except Exception as e:
            logger.error(f"Error getting subkeys from {key_path}: {e}")

        return subkeys

    def get_key_timestamp(self, key_path):
        """
        Get the last write time of a registry key.

        Args:
            key_path (str): Registry key path

        Returns:
            str: Formatted timestamp string or None
        """
        try:
            key = self.reg.open(key_path)
            timestamp = key.timestamp()
            return timestamp.strftime("%Y-%m-%d %H:%M:%S")
        except Registry.RegistryKeyNotFoundException:
            logger.warning(f"Key not found: {key_path}")
            return None
        except Exception as e:
            logger.error(f"Error getting timestamp for {key_path}: {e}")
            return None

    def search_value(self, value_name, case_sensitive=False):
        """
        Search for a specific value name across the entire registry hive.

        Args:
            value_name (str): Name of the value to search for
            case_sensitive (bool): Whether search should be case-sensitive

        Returns:
            list: List of tuples (key_path, value_data)
        """
        results = []
        search_name = value_name if case_sensitive else value_name.lower()

        def search_key(key, path=""):
            """Recursive helper function to search through keys."""
            try:
                # Search values in current key
                for value in key.values():
                    value_key_name = value.name() if case_sensitive else value.name().lower()
                    if search_name in value_key_name:
                        results.append((path, value.name(), value.value()))

                # Recurse into subkeys
                for subkey in key.subkeys():
                    subkey_path = f"{path}\\{subkey.name()}" if path else subkey.name()
                    search_key(subkey, subkey_path)

            except Exception as e:
                logger.debug(f"Error searching in key {path}: {e}")

        try:
            root = self.reg.root()
            search_key(root)
            logger.info(f"Found {len(results)} instances of '{value_name}'")
        except Exception as e:
            logger.error(f"Error during search: {e}")

        return results

    def export_to_dict(self):
        """
        Export all forensically valuable data to a structured dictionary.
        Alias for valuable_keys() for consistency with other methods.

        Returns:
            dict: Complete forensic data extraction
        """
        return self.valuable_keys()

    def get_hive_info(self):
        """
        Get metadata about the registry hive itself.

        Returns:
            dict: Hive metadata including root key name and timestamp
        """
        try:
            root = self.reg.root()
            return {
                'hive_name': root.name(),
                'hive_type': self.type,
                'file_path': self.file,
                'root_timestamp': root.timestamp().strftime("%Y-%m-%d %H:%M:%S")
            }
        except Exception as e:
            logger.error(f"Error getting hive info: {e}")
            return {}

    def _process_userassist(self, key):
        """
        Process UserAssist data - enumerate GUIDs and decode ROT13 values.

        Args:
            key: Registry key object for UserAssist

        Returns:
            dict: Processed UserAssist data with decoded program names
        """
        results = {}
        try:
            # UserAssist has GUID subkeys, each containing a Count subkey
            for guid_key in key.subkeys():
                guid_name = guid_key.name()
                try:
                    count_key = guid_key.subkey("Count")
                    guid_results = {}

                    for value in count_key.values():
                        # Decode ROT13 encoded value name
                        encoded_name = value.name()
                        decoded_name = rot13_decode(encoded_name)

                        # Get the binary data (contains execution count and timestamp)
                        data = value.value()
                        if isinstance(data, bytes) and len(data) >= 16:
                            # Parse UserAssist data structure
                            # Offset 4: Execution count (DWORD)
                            # Offset 60: Last execution time (FILETIME)
                            try:
                                import struct
                                if len(data) >= 72:
                                    exec_count = struct.unpack('<I', data[4:8])[0]
                                    # Last execution timestamp at offset 60
                                    timestamp_low = struct.unpack('<I', data[60:64])[0]
                                    timestamp_high = struct.unpack('<I', data[64:68])[0]
                                    timestamp = (timestamp_high << 32) | timestamp_low

                                    if timestamp > 0:
                                        last_exec = convert_epoch(timestamp)
                                        guid_results[decoded_name] = {
                                            'execution_count': exec_count,
                                            'last_executed': last_exec
                                        }
                                    else:
                                        guid_results[decoded_name] = {'execution_count': exec_count}
                                else:
                                    guid_results[decoded_name] = {'raw_data': data.hex()[:50] + '...'}
                            except Exception as e:
                                logger.warning(f"Error parsing UserAssist data: {e}")
                                guid_results[decoded_name] = {'raw_data': data.hex()[:50] + '...'}
                        else:
                            guid_results[decoded_name] = str(data)

                    if guid_results:
                        results[f"GUID_{guid_name}"] = guid_results

                except Registry.RegistryKeyNotFoundException:
                    logger.debug(f"Count key not found under {guid_name}")
                except Exception as e:
                    logger.warning(f"Error processing UserAssist GUID {guid_name}: {e}")

        except Exception as e:
            logger.error(f"Error in _process_userassist: {e}")

        return results

    def _process_recentdocs(self, key):
        """
        Process RecentDocs - enumerate file extensions and decode MRU lists.

        Args:
            key: Registry key object for RecentDocs

        Returns:
            dict: Recent documents organized by file type
        """
        results = {}
        try:
            # Get values from main RecentDocs key
            main_docs = print_values(key.values())
            if main_docs:
                results['_all_recent_'] = main_docs

            # Enumerate subkeys (file extensions)
            for subkey in key.subkeys():
                ext_name = subkey.name()
                ext_docs = print_values(subkey.values())
                if ext_docs:
                    results[f"extension_{ext_name}"] = ext_docs

        except Exception as e:
            logger.error(f"Error in _process_recentdocs: {e}")

        return results

    def _process_mountpoints(self, key):
        """
        Process MountPoints2 - enumerate mounted devices and remote shares.

        Args:
            key: Registry key object for MountPoints2

        Returns:
            dict: Mounted devices and their properties
        """
        results = {}
        try:
            for subkey in key.subkeys():
                device_name = subkey.name()
                device_info = {}

                # Get timestamp of when device was mounted
                device_info['last_mounted'] = subkey.timestamp().strftime("%Y-%m-%d %H:%M:%S")

                # Get any values
                values = print_values(subkey.values())
                if values:
                    device_info['properties'] = values

                results[device_name] = device_info

        except Exception as e:
            logger.error(f"Error in _process_mountpoints: {e}")

        return results

    def _process_typedpaths(self, key):
        """
        Process TypedPaths - paths typed in Windows Explorer address bar.

        Args:
            key: Registry key object for TypedPaths

        Returns:
            dict: List of typed paths in order
        """
        results = {}
        try:
            # TypedPaths are stored as url1, url2, url3, etc.
            values = print_values(key.values())

            # Sort by number to maintain order
            sorted_paths = {}
            for name, (value, vtype) in values.items():
                if name.startswith('url'):
                    try:
                        num = int(name[3:])
                        sorted_paths[num] = value
                    except ValueError:
                        sorted_paths[name] = value

            # Return in order
            for i in sorted(sorted_paths.keys()):
                results[f"path_{i}"] = sorted_paths[i]

        except Exception as e:
            logger.error(f"Error in _process_typedpaths: {e}")

        return results if results else print_values(key.values())

    def _process_sam_users(self, key, key_path):
        """
        Process SAM user account information.

        Args:
            key: Registry key object for SAM Users
            key_path: Full path to the key

        Returns:
            dict: User account information including RIDs and usernames
        """
        results = {}
        try:
            # If this is the Names subkey, enumerate usernames
            if key_path.endswith('Names'):
                usernames = []
                for subkey in key.subkeys():
                    username = subkey.name()
                    # Get the RID (Relative Identifier) from the default value
                    try:
                        rid_value = subkey.value('')
                        rid = rid_value.value()
                        if isinstance(rid, int):
                            usernames.append(f"{username} (RID: {rid})")
                        else:
                            usernames.append(username)
                    except:
                        usernames.append(username)

                if usernames:
                    results['_user_accounts_'] = usernames
                    results['_total_users_'] = len(usernames)

            # If this is the main Users key, enumerate RID subkeys
            else:
                for subkey in key.subkeys():
                    rid = subkey.name()
                    # Skip 'Names' subkey
                    if rid == 'Names':
                        continue

                    user_info = {}

                    # Get the F value (contains account metadata)
                    try:
                        f_value = subkey.value('F')
                        f_data = f_value.value()

                        if isinstance(f_data, bytes) and len(f_data) >= 0x30:
                            import struct

                            # Parse F structure
                            # Last login time at offset 0x08 (FILETIME)
                            last_login_low = struct.unpack('<I', f_data[0x08:0x0C])[0]
                            last_login_high = struct.unpack('<I', f_data[0x0C:0x10])[0]
                            last_login_ts = (last_login_high << 32) | last_login_low

                            if last_login_ts > 0:
                                user_info['last_login'] = convert_epoch(last_login_ts)

                            # Password last set at offset 0x18 (FILETIME)
                            pwd_set_low = struct.unpack('<I', f_data[0x18:0x1C])[0]
                            pwd_set_high = struct.unpack('<I', f_data[0x1C:0x20])[0]
                            pwd_set_ts = (pwd_set_high << 32) | pwd_set_low

                            if pwd_set_ts > 0:
                                user_info['password_last_set'] = convert_epoch(pwd_set_ts)

                            # Last failed login at offset 0x28 (FILETIME)
                            failed_login_low = struct.unpack('<I', f_data[0x28:0x2C])[0]
                            failed_login_high = struct.unpack('<I', f_data[0x2C:0x30])[0]
                            failed_login_ts = (failed_login_high << 32) | failed_login_low

                            if failed_login_ts > 0:
                                user_info['last_failed_login'] = convert_epoch(failed_login_ts)

                            # Login count at offset 0x40 (DWORD)
                            if len(f_data) >= 0x44:
                                login_count = struct.unpack('<I', f_data[0x40:0x44])[0]
                                user_info['login_count'] = login_count

                    except Exception as e:
                        logger.warning(f"Error parsing F value for RID {rid}: {e}")

                    # Get the V value (contains username and other info)
                    try:
                        v_value = subkey.value('V')
                        v_data = v_value.value()

                        if isinstance(v_data, bytes) and len(v_data) >= 0x30:
                            import struct

                            # Username offset is at 0x0C, length at 0x10
                            username_offset = struct.unpack('<I', v_data[0x0C:0x10])[0] + 0xCC
                            username_length = struct.unpack('<I', v_data[0x10:0x14])[0]

                            if username_offset < len(v_data) and username_length > 0:
                                username_data = v_data[username_offset:username_offset + username_length]
                                try:
                                    username = username_data.decode('utf-16le')
                                    user_info['username'] = username
                                except:
                                    pass

                            # Full name offset at 0x18, length at 0x1C
                            fullname_offset = struct.unpack('<I', v_data[0x18:0x1C])[0] + 0xCC
                            fullname_length = struct.unpack('<I', v_data[0x1C:0x20])[0]

                            if fullname_offset < len(v_data) and fullname_length > 0:
                                fullname_data = v_data[fullname_offset:fullname_offset + fullname_length]
                                try:
                                    fullname = fullname_data.decode('utf-16le')
                                    if fullname:
                                        user_info['full_name'] = fullname
                                except:
                                    pass

                            # Comment offset at 0x24, length at 0x28
                            comment_offset = struct.unpack('<I', v_data[0x24:0x28])[0] + 0xCC
                            comment_length = struct.unpack('<I', v_data[0x28:0x2C])[0]

                            if comment_offset < len(v_data) and comment_length > 0:
                                comment_data = v_data[comment_offset:comment_offset + comment_length]
                                try:
                                    comment = comment_data.decode('utf-16le')
                                    if comment:
                                        user_info['comment'] = comment
                                except:
                                    pass

                    except Exception as e:
                        logger.warning(f"Error parsing V value for RID {rid}: {e}")

                    if user_info:
                        results[f"RID_{rid}"] = user_info

        except Exception as e:
            logger.error(f"Error in _process_sam_users: {e}")

        return results

    def _process_security_policy(self, key, key_path):
        """
        Process SECURITY hive policy information.

        Args:
            key: Registry key object for Security Policy
            key_path: Full path to the key

        Returns:
            dict: Security policy information
        """
        results = {}
        try:
            # PolAdtEv contains audit policy settings
            if 'PolAdtEv' in key_path:
                try:
                    pol_value = key.value('')
                    pol_data = pol_value.value()

                    if isinstance(pol_data, bytes) and len(pol_data) >= 8:
                        import struct

                        # Audit policy categories (simplified)
                        audit_categories = {
                            0: 'System Events',
                            1: 'Logon/Logoff',
                            2: 'Object Access',
                            3: 'Privilege Use',
                            4: 'Detailed Tracking',
                            5: 'Policy Change',
                            6: 'Account Management',
                            7: 'Directory Service Access',
                            8: 'Account Logon'
                        }

                        audit_settings = {}
                        # Each category has 1 byte (0=None, 1=Success, 2=Failure, 3=Both)
                        for i, category in audit_categories.items():
                            if i < len(pol_data):
                                setting = pol_data[i]
                                audit_type = ['None', 'Success', 'Failure', 'Success and Failure'][setting] if setting < 4 else f'Unknown({setting})'
                                audit_settings[category] = audit_type

                        if audit_settings:
                            results['_audit_policy_'] = audit_settings

                except Exception as e:
                    logger.warning(f"Error parsing PolAdtEv: {e}")

            # PolPrDmS contains primary domain SID
            elif 'PolPrDmS' in key_path:
                try:
                    sid_value = key.value('')
                    sid_data = sid_value.value()

                    if isinstance(sid_data, bytes):
                        # Convert binary SID to string
                        sid_str = self._parse_sid(sid_data)
                        if sid_str:
                            results['primary_domain_sid'] = sid_str

                except Exception as e:
                    logger.warning(f"Error parsing PolPrDmS: {e}")

            # PolPrDmN contains primary domain name
            elif 'PolPrDmN' in key_path:
                try:
                    name_value = key.value('')
                    name_data = name_value.value()

                    if isinstance(name_data, bytes):
                        try:
                            domain_name = name_data.decode('utf-16le').rstrip('\x00')
                            if domain_name:
                                results['primary_domain_name'] = domain_name
                        except:
                            pass

                except Exception as e:
                    logger.warning(f"Error parsing PolPrDmN: {e}")

            # Policy\Accounts contains account policy settings
            elif 'Accounts' in key_path:
                try:
                    # Get all values from Accounts key
                    values = print_values(key.values())
                    if values:
                        results.update(values)
                except Exception as e:
                    logger.warning(f"Error parsing Accounts: {e}")

            # If no specific processing, extract all values
            if not results:
                results = print_values(key.values())

        except Exception as e:
            logger.error(f"Error in _process_security_policy: {e}")

        return results

    def _parse_sid(self, sid_bytes):
        """
        Parse binary SID to string format.

        Args:
            sid_bytes: Binary SID data

        Returns:
            str: SID in string format (S-1-5-21-...)
        """
        try:
            if not isinstance(sid_bytes, bytes) or len(sid_bytes) < 8:
                return None

            import struct

            # SID structure: revision(1), subauth_count(1), authority(6), subauth(4*n)
            revision = sid_bytes[0]
            subauth_count = sid_bytes[1]
            authority = struct.unpack('>Q', b'\x00\x00' + sid_bytes[2:8])[0]

            sid_str = f"S-{revision}-{authority}"

            # Read subauthorities (little-endian DWORDs)
            offset = 8
            for i in range(subauth_count):
                if offset + 4 <= len(sid_bytes):
                    subauth = struct.unpack('<I', sid_bytes[offset:offset+4])[0]
                    sid_str += f"-{subauth}"
                    offset += 4

            return sid_str

        except Exception as e:
            logger.warning(f"Error parsing SID: {e}")
            return None

    def print_results(self, results=None):
        """
        Pretty print the forensic results in a readable format.

        Args:
            results (dict): Results dictionary (if None, calls valuable_keys())
        """
        if results is None:
            results = self.valuable_keys()

        if not results:
            print(f"\n[!] No forensic data found in {self.type} hive")
            return

        print("\n" + "="*80)
        print(f"FORENSIC ANALYSIS - {self.type} HIVE")
        print("="*80)
        print(f"File: {self.file}\n")

        for key_path, values in results.items():
            print(f"\n[+] {key_path}")
            print("-" * 80)

            if isinstance(values, dict):
                for value_name, value_data in values.items():
                    # Handle special subkey indicators
                    if value_name.startswith('_') and value_name.endswith('_'):
                        if value_name == '_total_subkeys_':
                            print(f"    → Contains {value_data} subkeys")
                        elif value_name == '_subkeys_':
                            print(f"    → First subkeys: {', '.join(value_data[:5])}")
                            if len(value_data) > 5:
                                print(f"      (and {len(value_data) - 5} more...)")
                        elif value_name == '_all_recent_':
                            print(f"    → All Recent Documents:")
                            for doc_name, doc_data in value_data.items():
                                if isinstance(doc_data, tuple):
                                    print(f"      - {doc_name}: {doc_data[0]}")
                                else:
                                    print(f"      - {doc_name}: {doc_data}")
                        elif value_name == '_user_accounts_':
                            print(f"    → Local User Accounts:")
                            for username in value_data:
                                print(f"      - {username}")
                        elif value_name == '_total_users_':
                            print(f"    → Total Users: {value_data}")
                        elif value_name == '_audit_policy_':
                            print(f"    → Audit Policy Settings:")
                            for category, setting in value_data.items():
                                print(f"      {category}: {setting}")
                        continue

                    # Handle SAM RID entries
                    if value_name.startswith('RID_'):
                        rid = value_name.replace('RID_', '')
                        print(f"    → User RID: {rid}")
                        if isinstance(value_data, dict):
                            for prop, val in value_data.items():
                                print(f"      {prop}: {val}")
                        continue

                    # Handle UserAssist GUID entries
                    if value_name.startswith('GUID_'):
                        print(f"    → {value_name}")
                        if isinstance(value_data, dict):
                            for prog_name, prog_data in list(value_data.items())[:10]:  # Limit to 10 programs
                                if isinstance(prog_data, dict):
                                    exec_info = []
                                    if 'execution_count' in prog_data:
                                        exec_info.append(f"Count: {prog_data['execution_count']}")
                                    if 'last_executed' in prog_data:
                                        exec_info.append(f"Last: {prog_data['last_executed']}")
                                    info_str = ", ".join(exec_info) if exec_info else str(prog_data)
                                    print(f"      - {prog_name}")
                                    print(f"        {info_str}")
                                else:
                                    print(f"      - {prog_name}: {prog_data}")
                            if len(value_data) > 10:
                                print(f"      ... and {len(value_data) - 10} more programs")
                        continue

                    # Handle extension-specific recent docs
                    if value_name.startswith('extension_'):
                        ext = value_name.replace('extension_', '')
                        print(f"    → Files with extension: .{ext}")
                        if isinstance(value_data, dict):
                            for doc_name, doc_val in list(value_data.items())[:5]:
                                if isinstance(doc_val, tuple):
                                    print(f"      - {doc_name}: {doc_val[0]}")
                                else:
                                    print(f"      - {doc_name}: {doc_val}")
                            if len(value_data) > 5:
                                print(f"      ... and {len(value_data) - 5} more")
                        continue

                    # Handle mount points
                    if key_path and 'MountPoints2' in key_path:
                        print(f"    → Device: {value_name}")
                        if isinstance(value_data, dict):
                            for prop, val in value_data.items():
                                print(f"      {prop}: {val}")
                        continue

                    # Handle typed paths
                    if value_name.startswith('path_'):
                        print(f"    [{value_name.replace('path_', '')}] {value_data}")
                        continue

                    # Handle tuple format (value, type)
                    if isinstance(value_data, tuple) and len(value_data) == 2:
                        value, value_type = value_data

                        # Format based on data type
                        if isinstance(value, list):
                            # Handle multi-string values
                            print(f"    {value_name}:")
                            for item in value[:5]:  # Show first 5 items
                                if item:  # Skip empty strings
                                    print(f"      - {item}")
                            if len(value) > 5:
                                print(f"      ... and {len(value) - 5} more")
                        elif isinstance(value, str) and len(value) > 100:
                            # Truncate very long strings
                            print(f"    {value_name}:")
                            print(f"      {value[:100]}... (truncated)")
                        else:
                            print(f"    {value_name}: {value}")
                    else:
                        print(f"    {value_name}: {value_data}")
            else:
                print(f"    Value: {values}")

        print("\n" + "="*80)
        print(f"Total Keys Extracted: {len(results)}")
        print("="*80 + "\n")

    def export_to_json(self, output_file, results=None):
        """
        Export forensic results to JSON file.

        Args:
            output_file (str): Path to output JSON file
            results (dict): Results dictionary (if None, calls valuable_keys())
        """
        import json

        if results is None:
            results = self.valuable_keys()

        # Convert tuple values to lists for JSON serialization
        json_results = {}
        for key_path, values in results.items():
            json_results[key_path] = {}
            if isinstance(values, dict):
                for value_name, value_data in values.items():
                    if isinstance(value_data, tuple):
                        json_results[key_path][value_name] = {
                            'value': str(value_data[0]),
                            'type': str(value_data[1])
                        }
                    else:
                        json_results[key_path][value_name] = str(value_data)

        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(json_results, f, indent=4, ensure_ascii=False)
            print(f"[+] Results exported to: {output_file}")
        except Exception as e:
            logger.error(f"Error exporting to JSON: {e}")

    def export_to_csv(self, output_file, results=None):
        """
        Export forensic results to CSV file.

        Args:
            output_file (str): Path to output CSV file
            results (dict): Results dictionary (if None, calls valuable_keys())
        """
        import csv

        if results is None:
            results = self.valuable_keys()

        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Registry Key', 'Value Name', 'Value Data', 'Value Type'])

                for key_path, values in results.items():
                    if isinstance(values, dict):
                        for value_name, value_data in values.items():
                            if isinstance(value_data, tuple) and len(value_data) == 2:
                                writer.writerow([key_path, value_name, str(value_data[0]), str(value_data[1])])
                            else:
                                writer.writerow([key_path, value_name, str(value_data), 'N/A'])

            print(f"[+] Results exported to: {output_file}")
        except Exception as e:
            logger.error(f"Error exporting to CSV: {e}")


# Main execution for testing
if __name__ == "__main__":
    import sys

    print("="*80)
    print("ToolBox Forensics Registry Parser")
    print("="*80)

    if len(sys.argv) < 3:
        print("\nUsage: python toolbox_registry.py <registry_file> <hive_type>")
        print("\nHive Types: SOFTWARE, SYSTEM, SAM, NTUSER, SECURITY, USRCLASS")
        print("\nExamples:")
        print("  python toolbox_registry.py C:\\Cases\\Evidence\\SOFTWARE SOFTWARE")
        print("  python toolbox_registry.py ./NTUSER.DAT NTUSER")
        print("  python toolbox_registry.py ./SYSTEM SYSTEM")
        sys.exit(1)

    registry_file = sys.argv[1]
    hive_type = sys.argv[2].upper()

    try:
        # Initialize the registry analyzer
        print(f"\n[*] Loading {hive_type} hive: {registry_file}")
        reg_analyzer = ToolboxRegistry(registry_file, hive_type)

        # Get hive information
        hive_info = reg_analyzer.get_hive_info()
        print(f"[*] Hive Root: {hive_info.get('hive_name', 'Unknown')}")
        print(f"[*] Last Modified: {hive_info.get('root_timestamp', 'Unknown')}")

        # Extract forensic data
        print(f"[*] Extracting forensic artifacts...\n")
        results = reg_analyzer.valuable_keys()

        # Print results to console
        reg_analyzer.print_results(results)

        # Optional: Export to files (uncomment to use)
        # if results:
        #     base_filename = f"{hive_type}_forensics"
        #     reg_analyzer.export_to_json(f"{base_filename}.json", results)
        #     reg_analyzer.export_to_csv(f"{base_filename}.csv", results)

    except FileNotFoundError:
        print(f"\n[!] ERROR: Registry file not found: {registry_file}")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] ERROR: {e}")
        sys.exit(1)