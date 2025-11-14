import sys
from datetime import datetime, timedelta
from enum import IntEnum


def convert_timestamp(timestamp):
    """Convert Windows FILETIME to datetime string"""
    if timestamp == 0:
        return "Not set"
    return str(datetime(1601, 1, 1) + timedelta(microseconds = timestamp / 10.))


class DriveType(IntEnum):
    DRIVE_UNKNOWN = 0
    DRIVE_NO_ROOT_DIR = 1
    DRIVE_REMOVABLE = 2
    DRIVE_FIXED = 3
    DRIVE_REMOTE = 4
    DRIVE_CDROM = 5
    DRIVE_RAMDISK = 6


class ShowCommand(IntEnum):
    SW_SHOWNORMAL = 1
    SW_SHOWMAXIMIZED = 3
    SW_SHOWMINNOACTIVE = 7


class ToolboxLnk:
    def __init__(self, lnk):
        self.lnk_file = lnk
        self.header = None

        # Initialize all potential attributes
        self.created_timestamp = None
        self.access_timestamp = None
        self.write_timestamp = None
        self.file_size = None
        self.icon_index = None
        self.show_command = None
        self.hot_keys_flag = None
        self.enabled_flags = []
        self.LinkTargetIDList = None
        self.LinkInfoSize = None
        self.link_info_start = None
        self.id_list_size = 0
        self.VolumeID = None
        self.local_base_path = None
        self.common_suffix_path = None

        # String data attributes
        self.name_string = None
        self.relative_path = None
        self.working_dir = None
        self.command_line_arguments = None
        self.icon_location = None

        # Extra data blocks
        self.extra_data_blocks = []

        with open(self.lnk_file, 'rb') as f:
            # Validate signature
            signature = f.read(4)
            if signature != b'\x4C\x00\x00\x00':
                raise ValueError(f"Invalid LNK Signature: {signature.hex()}")

            f.seek(0)
            self._parse_header(f)

            # Parse optional structures based on flags
            if 'HasLinkTargetIDList' in self.enabled_flags:
                self.LinkTargetIDList = self._parse_target_id_list(f)

            if 'HasLinkInfo' in self.enabled_flags:
                self._parse_link_info(f)

            # Parse string data
            self._parse_string_data(f)

            # Parse extra data blocks
            self._parse_extra_data(f)

        self.print_lnk_results(self.__dict__)

    def _parse_header(self, f):
        """Parse the ShellLinkHeader (76 bytes)"""
        self.header = {
            'signature': f.read(4).hex(),
            'clsid': f.read(16).hex(),
            'link_flags': int.from_bytes(f.read(4), 'little'),
            'file_attributes': int.from_bytes(f.read(4), 'little'),
            'header_size': 76
        }

        self.created_timestamp = convert_timestamp(int.from_bytes(f.read(8), 'little'))
        self.access_timestamp = convert_timestamp(int.from_bytes(f.read(8), 'little'))
        self.write_timestamp = convert_timestamp(int.from_bytes(f.read(8), 'little'))
        self.file_size = int.from_bytes(f.read(4), 'little')
        self.icon_index = int.from_bytes(f.read(4), 'little', signed = True)

        show_cmd = int.from_bytes(f.read(4), 'little')
        self.show_command = ShowCommand(show_cmd).name if show_cmd in [1, 3, 7] else f"Unknown ({show_cmd})"

        self.hot_keys_flag = int.from_bytes(f.read(2), 'little')
        f.read(2)  # Reserved1
        f.read(4)  # Reserved2
        f.read(4)  # Reserved3

        self.enabled_flags = self._parse_link_flags()

    def _parse_link_flags(self):
        """Parse LinkFlags structure (section 2.1.1)"""
        link_flags = self.header["link_flags"]
        flags = [
            "HasLinkTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath",
            "HasWorkingDir", "HasArguments", "HasIconLocation", "IsUnicode",
            "ForceNoLinkInfo", "HasExpString", "RunInSeparateProcess", "Unused1",
            "HasDarwinID", "RunAsUser", "HasExpIcon", "NoPidlAlias",
            "Unused2", "RunWithShimLayer", "ForceNoLinkTrack", "EnableTargetMetadata",
            "DisableLinkPathTracking", "DisableKnownFolderTracking",
            "DisableKnownFolderAlias", "AllowLinkToLink", "UnaliasOnSave",
            "PreferEnvironmentPath", "KeepLocalIDListForUNCTarget"
        ]

        binary_flags = format(link_flags, '032b')
        return [flag for i, flag in enumerate(flags) if binary_flags[31 - i] == '1']

    def _parse_target_id_list(self, f):
        """Parse LinkTargetIDList structure (section 2.2)"""
        f.seek(76)
        self.id_list_size = int.from_bytes(f.read(2), 'little')

        parsed_data = []
        bytes_read = 0

        while bytes_read < self.id_list_size:
            item_id_size = int.from_bytes(f.read(2), 'little')
            bytes_read += 2

            if item_id_size == 0x0000:  # Terminal ID
                break

            item_data = f.read(item_id_size - 2)
            bytes_read += (item_id_size - 2)
            parsed_data.append(
                {
                    "ItemIDSize": item_id_size,
                    "Data": item_data.hex()
                })

        return parsed_data

    def _parse_link_info(self, f):
        """Parse LinkInfo structure (section 2.3)"""
        self.link_info_start = 76 + 2 + self.id_list_size
        f.seek(self.link_info_start)

        self.LinkInfoSize = int.from_bytes(f.read(4), 'little')
        self.LinkInfoHeaderSize = int.from_bytes(f.read(4), 'little')
        self.LinkInfoFlags = int.from_bytes(f.read(4), 'little')

        # Parse link info flags
        self.enable_link_flags = []
        if self.LinkInfoFlags & 0x01:
            self.enable_link_flags.append('VolumeIDAndLocalBasePath')
        if self.LinkInfoFlags & 0x02:
            self.enable_link_flags.append('CommonNetworkRelativeLinkAndPathSuffix')

        # Read offsets
        self.VolumeIDOffset = int.from_bytes(f.read(4), 'little')
        self.LocalBasePathOffset = int.from_bytes(f.read(4), 'little')
        self.CommonNetworkRelativeLinkOffset = int.from_bytes(f.read(4), 'little')
        self.CommonPathSuffixOffset = int.from_bytes(f.read(4), 'little')

        # Optional Unicode offsets (if header size >= 0x24)
        if self.LinkInfoHeaderSize >= 0x00000024:
            self.LocalBasePathOffsetUnicode = int.from_bytes(f.read(4), 'little')
            self.CommonPathSuffixOffsetUnicode = int.from_bytes(f.read(4), 'little')
        else:
            self.LocalBasePathOffsetUnicode = 0
            self.CommonPathSuffixOffsetUnicode = 0

        # Parse VolumeID if present
        if 'VolumeIDAndLocalBasePath' in self.enable_link_flags and self.VolumeIDOffset:
            self.VolumeID = self._parse_volume_id(f)

        # Parse LocalBasePath - use Unicode if IsUnicode flag is set AND Unicode offset is available
        if 'VolumeIDAndLocalBasePath' in self.enable_link_flags and self.LocalBasePathOffset:
            if 'IsUnicode' in self.enabled_flags and self.LocalBasePathOffsetUnicode:
                self.local_base_path = self._read_null_terminated_string(
                    f, self.link_info_start + self.LocalBasePathOffsetUnicode, 'utf-16-le'
                )
            else:
                self.local_base_path = self._read_null_terminated_string(
                    f, self.link_info_start + self.LocalBasePathOffset, 'cp1252'
                )

        # Parse CommonPathSuffix - use Unicode if IsUnicode flag is set AND Unicode offset is available
        if self.CommonPathSuffixOffset:
            if 'IsUnicode' in self.enabled_flags and self.CommonPathSuffixOffsetUnicode:
                self.common_suffix_path = self._read_null_terminated_string(
                    f, self.link_info_start + self.CommonPathSuffixOffsetUnicode, 'utf-16-le'
                )
            else:
                self.common_suffix_path = self._read_null_terminated_string(
                    f, self.link_info_start + self.CommonPathSuffixOffset, 'cp1252'
                )

    def _parse_volume_id(self, f):
        """Parse VolumeID structure (section 2.3.1)"""
        volume_start = self.link_info_start + self.VolumeIDOffset
        f.seek(volume_start)

        volume_id_size = int.from_bytes(f.read(4), 'little')
        drive_type = int.from_bytes(f.read(4), 'little')
        drive_serial = int.from_bytes(f.read(4), 'little')
        volume_label_offset = int.from_bytes(f.read(4), 'little')

        # Check for Unicode volume label (spec says if offset == 0x14, read Unicode offset next)
        volume_label_offset_unicode = None
        if volume_label_offset == 0x00000014:
            volume_label_offset_unicode = int.from_bytes(f.read(4), 'little')

        # Read volume label - prefer Unicode if IsUnicode flag is set and Unicode offset is available
        if 'IsUnicode' in self.enabled_flags and volume_label_offset_unicode:
            label_pos = volume_start + volume_label_offset_unicode
            encoding = 'utf-16-le'
        else:
            label_pos = volume_start + volume_label_offset
            encoding = 'cp1252'

        volume_label = self._read_null_terminated_string(f, label_pos, encoding)

        return {
            'volume_id_size': volume_id_size,
            'drive_type': DriveType(
                drive_type).name if drive_type in DriveType._value2member_map_ else f"Unknown ({drive_type})",
            'drive_serial_number': f"0x{drive_serial:08X}",
            'volume_label_offset': volume_label_offset,
            'volume_label': volume_label,
            'encoding_used': encoding
        }

    def _read_null_terminated_string(self, f, position, encoding='utf-8'):
        """Read a null-terminated string from file"""
        f.seek(position)
        string_bytes = bytearray()

        if encoding == 'utf-16-le':
            while True:
                byte_pair = f.read(2)
                if not byte_pair or byte_pair == b'\x00\x00':
                    break
                string_bytes.extend(byte_pair)
        else:
            while True:
                byte = f.read(1)
                if not byte or byte == b'\x00':
                    break
                string_bytes.extend(byte)

        try:
            return string_bytes.decode(encoding)
        except UnicodeDecodeError:
            return string_bytes.decode(encoding, errors = 'replace')

    def _parse_string_data(self, f):
        """Parse StringData structures (section 2.4)"""
        # Calculate starting position
        start_pos = self.header['header_size'] + 2 + self.id_list_size
        if hasattr(self, 'LinkInfoSize') and self.LinkInfoSize:
            start_pos += self.LinkInfoSize

        f.seek(start_pos)

        string_sections = [
            ('name_string', 'HasName'),
            ('relative_path', 'HasRelativePath'),
            ('working_dir', 'HasWorkingDir'),
            ('command_line_arguments', 'HasArguments'),
            ('icon_location', 'HasIconLocation')
        ]

        for attr_name, flag_name in string_sections:
            if flag_name not in self.enabled_flags:
                setattr(self, attr_name, None)
                continue

            try:
                char_count = int.from_bytes(f.read(2), 'little')
                if char_count == 0:
                    setattr(self, attr_name, None)
                    continue

                byte_size = char_count * (2 if 'IsUnicode' in self.enabled_flags else 1)
                data = f.read(byte_size)
                encoding = 'utf-16-le' if 'IsUnicode' in self.enabled_flags else 'cp1252'
                setattr(self, attr_name, data.decode(encoding, errors = 'replace'))
            except Exception as e:
                print(f"Error parsing {attr_name}: {e}")
                setattr(self, attr_name, None)

    def _parse_extra_data(self, f):
        """Parse ExtraData structures (section 2.5)"""
        self.extra_data_blocks = []

        while True:
            try:
                block_size = int.from_bytes(f.read(4), 'little')

                # Terminal block
                if block_size < 0x00000004:
                    break

                block_signature = int.from_bytes(f.read(4), 'little')

                # Read remaining block data
                remaining_data = f.read(block_size - 8)

                # Parse block based on signature
                block_info = self._parse_extra_data_block(block_signature, remaining_data, block_size)
                self.extra_data_blocks.append(block_info)

            except Exception as e:
                print(f"Error parsing extra data: {e}")
                break

    def _parse_extra_data_block(self, signature, data, block_size):
        """Parse specific extra data block types"""
        block_info = {
            'block_size': block_size,
            'block_signature': f"0x{signature:08X}",
            'block_type': self._get_block_type_name(signature)
        }

        # Parse based on signature
        if signature == 0xA0000001:  # EnvironmentVariableDataBlock
            block_info['parsed_data'] = self._parse_environment_variable_block(data)
        elif signature == 0xA0000002:  # ConsoleDataBlock
            block_info['parsed_data'] = self._parse_console_data_block(data)
        elif signature == 0xA0000003:  # TrackerDataBlock
            block_info['parsed_data'] = self._parse_tracker_data_block(data)
        elif signature == 0xA0000004:  # ConsoleFEDataBlock
            block_info['parsed_data'] = self._parse_console_fe_data_block(data)
        elif signature == 0xA0000005:  # SpecialFolderDataBlock
            block_info['parsed_data'] = self._parse_special_folder_data_block(data)
        elif signature == 0xA0000006:  # DarwinDataBlock
            block_info['parsed_data'] = self._parse_darwin_data_block(data)
        elif signature == 0xA0000007:  # IconEnvironmentDataBlock
            block_info['parsed_data'] = self._parse_icon_environment_data_block(data)
        elif signature == 0xA0000008:  # ShimDataBlock
            block_info['parsed_data'] = self._parse_shim_data_block(data)
        elif signature == 0xA0000009:  # PropertyStoreDataBlock
            block_info['parsed_data'] = self._parse_property_store_data_block(data)
        elif signature == 0xA000000B:  # KnownFolderDataBlock
            block_info['parsed_data'] = self._parse_known_folder_data_block(data)
        elif signature == 0xA000000C:  # VistaAndAboveIDListDataBlock
            block_info['parsed_data'] = self._parse_vista_idlist_data_block(data)
        else:
            block_info['raw_data_hex'] = data.hex()

        return block_info

    def _parse_environment_variable_block(self, data):
        """Parse EnvironmentVariableDataBlock (section 2.5.4) - 0x314 bytes"""
        if len(data) < 520:
            return {'error': 'Insufficient data'}

        # According to spec: 260 bytes ANSI, 520 bytes Unicode
        target_ansi = data[0:260].rstrip(b'\x00').decode('cp1252', errors = 'replace')

        # Only parse Unicode if enough data exists
        target_unicode = None
        if len(data) >= 780:
            target_unicode = data[260:780].rstrip(b'\x00\x00').decode('utf-16-le', errors = 'replace')

        result = {}

        # If IsUnicode flag is set, prefer Unicode; otherwise use ANSI
        if 'IsUnicode' in self.enabled_flags:
            if target_unicode:
                result['target_path'] = target_unicode if target_unicode else '(empty)'
                result['encoding'] = 'UTF-16 LE (Unicode)'
            else:
                result['target_path'] = target_ansi if target_ansi else '(empty)'
                result['encoding'] = 'CP1252 (ANSI) - Unicode data not available'
        else:
            result['target_path'] = target_ansi if target_ansi else '(empty)'
            result['encoding'] = 'CP1252 (ANSI)'

        return result

    def _parse_console_data_block(self, data):
        """Parse ConsoleDataBlock (section 2.5.1) - 0xCC bytes"""
        if len(data) < 196:
            return {'error': 'Insufficient data'}

        fill_attr = int.from_bytes(data[0:2], 'little')
        popup_fill = int.from_bytes(data[2:4], 'little')
        font_family = int.from_bytes(data[28:32], 'little')
        font_weight = int.from_bytes(data[32:36], 'little')
        cursor_size = int.from_bytes(data[100:104], 'little')

        # Parse color table (16 RGB values at offset 132)
        color_table = []
        for i in range(16):
            offset = 132 + (i * 4)
            if offset + 4 <= len(data):
                rgb_val = int.from_bytes(data[offset:offset + 4], 'little')
                r = rgb_val & 0xFF
                g = (rgb_val >> 8) & 0xFF
                b = (rgb_val >> 16) & 0xFF
                color_table.append(f"RGB({r}, {g}, {b})")

        return {
            'fill_attributes': self._decode_console_colors(fill_attr),
            'popup_fill_attributes': self._decode_console_colors(popup_fill),
            'screen_buffer_size': f"{int.from_bytes(data[4:6], 'little', signed = True)} x {int.from_bytes(data[6:8], 'little', signed = True)} characters",
            'window_size': f"{int.from_bytes(data[8:10], 'little', signed = True)} x {int.from_bytes(data[10:12], 'little', signed = True)} characters",
            'window_position': f"X: {int.from_bytes(data[12:14], 'little', signed = True)}, Y: {int.from_bytes(data[14:16], 'little', signed = True)} pixels",
            'font_size': f"{int.from_bytes(data[24:28], 'little')} pixels",
            'font_family': self._decode_font_family(font_family),
            'font_weight': self._decode_font_weight(font_weight),
            'face_name': data[36:100].rstrip(b'\x00\x00').decode('utf-16-le', errors = 'replace'),
            'cursor_size': self._decode_cursor_size(cursor_size),
            'full_screen': 'On' if int.from_bytes(data[104:108], 'little') else 'Off',
            'quick_edit': 'Enabled' if int.from_bytes(data[108:112], 'little') else 'Disabled',
            'insert_mode': 'Enabled' if int.from_bytes(data[112:116], 'little') else 'Disabled',
            'auto_position': 'Enabled' if int.from_bytes(data[116:120], 'little') else 'Disabled',
            'history_buffer_size': f"{int.from_bytes(data[120:124], 'little')} characters",
            'number_of_history_buffers': int.from_bytes(data[124:128], 'little'),
            'history_no_dup': 'Duplicates Allowed' if int.from_bytes(data[128:132], 'little') else 'No Duplicates',
            'color_table': color_table
        }

    def _decode_console_colors(self, attr_value):
        """Decode console color attributes"""
        colors = []
        color_names = ['Blue', 'Green', 'Red', 'Intensity']

        # Foreground colors (bits 0-3)
        fg_colors = []
        for i, name in enumerate(color_names):
            if attr_value & (1 << i):
                fg_colors.append(name)

        # Background colors (bits 4-7)
        bg_colors = []
        for i, name in enumerate(color_names):
            if attr_value & (1 << (i + 4)):
                bg_colors.append(name)

        fg_text = '+'.join(fg_colors) if fg_colors else 'Black'
        bg_text = '+'.join(bg_colors) if bg_colors else 'Black'

        return f"Foreground: {fg_text}, Background: {bg_text}"

    def _decode_font_family(self, family_value):
        """Decode font family"""
        family_base = family_value & 0xF0
        pitch = family_value & 0x0F

        family_names = {
            0x00: "Don't Care",
            0x10: "Roman (serif)",
            0x20: "Swiss (sans-serif)",
            0x30: "Modern (fixed-width)",
            0x40: "Script",
            0x50: "Decorative"
        }

        pitch_names = {
            0x00: "Default pitch",
            0x01: "Fixed pitch",
            0x02: "Vector",
            0x04: "TrueType",
            0x08: "Device-specific"
        }

        family = family_names.get(family_base, f"Unknown (0x{family_base:02X})")
        pitch_str = pitch_names.get(pitch, f"Unknown (0x{pitch:02X})")

        return f"{family}, {pitch_str}"

    def _decode_font_weight(self, weight):
        """Decode font weight"""
        if weight >= 700:
            return f"Bold ({weight})"
        elif weight >= 600:
            return f"Semi-bold ({weight})"
        elif weight >= 400:
            return f"Regular ({weight})"
        else:
            return f"Light ({weight})"

    def _decode_cursor_size(self, size):
        """Decode cursor size"""
        if size <= 25:
            return f"Small ({size}%)"
        elif size <= 50:
            return f"Medium ({size}%)"
        else:
            return f"Large ({size}%)"

    def _parse_tracker_data_block(self, data):
        """Parse TrackerDataBlock (section 2.5.10) - 0x60 bytes
        This contains distributed link tracking data including potential MAC addresses in GUIDs"""
        if len(data) < 88:
            return {'error': 'Insufficient data'}

        length = int.from_bytes(data[0:4], 'little')
        version = int.from_bytes(data[4:8], 'little')
        machine_id = data[8:24].rstrip(b'\x00').decode('cp1252', errors = 'replace')

        # Parse GUIDs - these may contain MAC addresses in the last 6 bytes
        droid_1 = data[24:40]
        droid_2 = data[40:56]
        droid_birth_1 = data[56:72]
        droid_birth_2 = data[72:88]

        return {
            'length': f"{length} bytes",
            'version': version,
            'machine_id': machine_id,
            'droid_volume_id': self._parse_guid_with_mac(droid_1, "Volume ID"),
            'droid_object_id': self._parse_guid_with_mac(droid_2, "Object ID"),
            'droid_birth_volume_id': self._parse_guid_with_mac(droid_birth_1, "Birth Volume ID"),
            'droid_birth_object_id': self._parse_guid_with_mac(droid_birth_2, "Birth Object ID"),
            'note': 'Droid GUIDs are used by Windows Distributed Link Tracking service'
        }

    def _parse_guid_with_mac(self, guid_bytes, guid_type):
        """Parse GUID and check for potential MAC address in last 6 bytes"""
        if len(guid_bytes) != 16:
            return {"error": "Invalid GUID length"}

        # Format as standard GUID
        d1 = int.from_bytes(guid_bytes[0:4], 'little')
        d2 = int.from_bytes(guid_bytes[4:6], 'little')
        d3 = int.from_bytes(guid_bytes[6:8], 'little')
        d4 = guid_bytes[8:10].hex().upper()
        d5 = guid_bytes[10:16].hex().upper()

        guid_str = f"{d1:08X}-{d2:04X}-{d3:04X}-{d4}-{d5}"

        # Check if last 6 bytes could be a MAC address
        potential_mac = guid_bytes[10:16]
        mac_str = ':'.join(f'{b:02X}' for b in potential_mac)

        # Check if it looks like a valid MAC
        is_valid_mac = (potential_mac != b'\x00' * 6 and
                        potential_mac != b'\xff' * 6 and
                        any(b != 0 for b in potential_mac))

        result = {
            'type': guid_type,
            'guid': guid_str,
            'timestamp': self._decode_guid_timestamp(guid_bytes),
        }

        if is_valid_mac:
            result['possible_mac_address'] = mac_str

        return result

    def _decode_guid_timestamp(self, guid_bytes):
        """Try to decode timestamp from GUID if it's a version 1 (time-based) GUID"""
        version = (guid_bytes[7] >> 4) & 0x0F

        if version == 1:
            # Extract time fields
            time_low = int.from_bytes(guid_bytes[0:4], 'little')
            time_mid = int.from_bytes(guid_bytes[4:6], 'little')
            time_hi_and_version = int.from_bytes(guid_bytes[6:8], 'little')
            time_hi = time_hi_and_version & 0x0FFF

            # Combine into 60-bit timestamp
            timestamp = (time_hi << 48) | (time_mid << 32) | time_low

            # UUID timestamp is 100-nanosecond intervals since October 15, 1582
            uuid_epoch = datetime(1582, 10, 15)
            unix_epoch = datetime(1970, 1, 1)
            epoch_diff = (unix_epoch - uuid_epoch).total_seconds() * 10000000

            unix_timestamp = (timestamp - epoch_diff) / 10000000

            try:
                dt = datetime.fromtimestamp(unix_timestamp)
                return f"Version 1 GUID created: {dt.strftime('%Y-%m-%d %H:%M:%S')}"
            except:
                return "Version 1 GUID (timestamp decode failed)"
        else:
            return f"Version {version} GUID (not time-based)"

    def _parse_console_fe_data_block(self, data):
        """Parse ConsoleFEDataBlock (section 2.5.2) - 0xC bytes"""
        if len(data) < 4:
            return {'error': 'Insufficient data'}

        code_page = int.from_bytes(data[0:4], 'little')

        return {
            'code_page': code_page,
            'code_page_name': self._get_code_page_name(code_page)
        }

    def _get_code_page_name(self, cp):
        """Map code page number to name"""
        code_pages = {
            437: "OEM United States",
            850: "OEM Multilingual Latin 1",
            852: "OEM Latin 2",
            855: "OEM Cyrillic (Russian)",
            857: "OEM Turkish",
            860: "OEM Portuguese",
            861: "OEM Icelandic",
            862: "OEM Hebrew",
            863: "OEM French Canadian",
            864: "OEM Arabic",
            865: "OEM Nordic",
            866: "OEM Russian (Cyrillic)",
            869: "OEM Modern Greek",
            874: "Windows Thai",
            932: "Japanese (Shift-JIS)",
            936: "Simplified Chinese (GB2312)",
            949: "Korean",
            950: "Traditional Chinese (Big5)",
            1200: "Unicode (UTF-16LE)",
            1201: "Unicode (UTF-16BE)",
            1250: "Windows Central European",
            1251: "Windows Cyrillic",
            1252: "Windows Western European (Latin 1)",
            1253: "Windows Greek",
            1254: "Windows Turkish",
            1255: "Windows Hebrew",
            1256: "Windows Arabic",
            1257: "Windows Baltic",
            1258: "Windows Vietnamese",
            65001: "Unicode (UTF-8)"
        }

        return code_pages.get(cp, f"Unknown Code Page")

    def _parse_special_folder_data_block(self, data):
        """Parse SpecialFolderDataBlock (section 2.5.9) - 0x10 bytes"""
        if len(data) < 8:
            return {'error': 'Insufficient data'}

        folder_id = int.from_bytes(data[0:4], 'little')
        offset = int.from_bytes(data[4:8], 'little')

        return {
            'special_folder_id': folder_id,
            'special_folder_name': self._get_special_folder_name(folder_id),
            'offset': f"{offset} bytes"
        }

    def _get_special_folder_name(self, folder_id):
        """Map special folder ID to name (CSIDL values)"""
        folders = {
            0x0000: "Desktop",
            0x0002: "Programs (Start Menu)",
            0x0005: "My Documents",
            0x0006: "Favorites",
            0x0007: "Startup",
            0x0008: "Recent",
            0x0009: "SendTo",
            0x000a: "Recycle Bin",
            0x000b: "Start Menu",
            0x000d: "My Music",
            0x000e: "My Videos",
            0x0010: "Desktop Directory",
            0x0011: "My Computer",
            0x0013: "Network Neighborhood",
            0x0014: "Fonts",
            0x0015: "Templates",
            0x0016: "Common Start Menu",
            0x0017: "Common Programs",
            0x0018: "Common Startup",
            0x0019: "Common Desktop",
            0x001a: "Application Data",
            0x001b: "Print Hood",
            0x001c: "Local Settings\\Application Data",
            0x0020: "Windows\\Fonts",
            0x0023: "Common Favorites",
            0x0025: "System32",
            0x0026: "Program Files",
            0x0027: "My Pictures",
            0x0028: "User Profile",
            0x002b: "Common Templates",
            0x002e: "Common Application Data",
            0x0029: "System",
            0x002a: "Program Files",
            0x002f: "Common Documents"
        }

        return folders.get(folder_id, f"Unknown Special Folder (0x{folder_id:04X})")

    def _parse_darwin_data_block(self, data):
        """Parse DarwinDataBlock (section 2.5.3) - 0x314 bytes"""
        if len(data) < 520:
            return {'error': 'Insufficient data'}

        darwin_ansi = data[0:260].rstrip(b'\x00').decode('cp1252', errors = 'replace')

        # Only parse Unicode if enough data
        darwin_unicode = None
        if len(data) >= 780:
            darwin_unicode = data[260:780].rstrip(b'\x00\x00').decode('utf-16-le', errors = 'replace')

        result = {}

        # Prefer Unicode if IsUnicode flag is set
        if 'IsUnicode' in self.enabled_flags:
            if darwin_unicode:
                result['darwin_identifier'] = darwin_unicode if darwin_unicode else '(empty)'
                result['encoding'] = 'UTF-16 LE (Unicode)'
            else:
                result['darwin_identifier'] = darwin_ansi if darwin_ansi else '(empty)'
                result['encoding'] = 'CP1252 (ANSI) - Unicode not available'
        else:
            result['darwin_identifier'] = darwin_ansi if darwin_ansi else '(empty)'
            result['encoding'] = 'CP1252 (ANSI)'

        result['note'] = 'Windows Installer (MSI) application descriptor'

        return result

    def _parse_icon_environment_data_block(self, data):
        """Parse IconEnvironmentDataBlock (section 2.5.5) - 0x314 bytes"""
        if len(data) < 520:
            return {'error': 'Insufficient data'}

        target_ansi = data[0:260].rstrip(b'\x00').decode('cp1252', errors = 'replace')

        # Only parse Unicode if enough data
        target_unicode = None
        if len(data) >= 780:
            target_unicode = data[260:780].rstrip(b'\x00\x00').decode('utf-16-le', errors = 'replace')

        result = {}

        # Prefer Unicode if IsUnicode flag is set
        if 'IsUnicode' in self.enabled_flags:
            if target_unicode:
                result['icon_path'] = target_unicode if target_unicode else '(empty)'
                result['encoding'] = 'UTF-16 LE (Unicode)'
            else:
                result['icon_path'] = target_ansi if target_ansi else '(empty)'
                result['encoding'] = 'CP1252 (ANSI) - Unicode not available'
        else:
            result['icon_path'] = target_ansi if target_ansi else '(empty)'
            result['encoding'] = 'CP1252 (ANSI)'

        result['note'] = 'Icon path with environment variables'

        return result

    def _parse_shim_data_block(self, data):
        """Parse ShimDataBlock (section 2.5.8) - variable size >= 0x88 bytes"""
        if len(data) < 4:
            return {'error': 'Insufficient data'}

        # Try to decode as Unicode string
        layer_name = data.rstrip(b'\x00\x00').decode('utf-16-le', errors = 'replace')

        return {
            'layer_name': layer_name if layer_name else '(empty)',
            'note': 'Application compatibility shim layer'
        }

    def _parse_property_store_data_block(self, data):
        """Parse PropertyStoreDataBlock (section 2.5.7) - variable size"""
        return {
            'note': 'PropertyStore format is complex (see MS-PROPSTORE)',
            'size': f"{len(data)} bytes",
            'hex_preview': data[:64].hex() + ('...' if len(data) > 64 else '')
        }

    def _parse_known_folder_data_block(self, data):
        """Parse KnownFolderDataBlock (section 2.5.6) - 0x1C bytes"""
        if len(data) < 20:
            return {'error': 'Insufficient data'}

        known_folder_guid = self._format_guid(data[0:16])
        offset = int.from_bytes(data[16:20], 'little')

        return {
            'known_folder_id': known_folder_guid,
            'known_folder_name': self._get_known_folder_name(known_folder_guid),
            'offset': f"{offset} bytes"
        }

    def _get_known_folder_name(self, guid_str):
        """Map known folder GUID to name"""
        known_folders = {
            "B4BFCC3A-DB2C-424C-B029-7FE99A87C641": "Desktop",
            "FDD39AD0-238F-46AF-ADB4-6C85480369C7": "Documents",
            "374DE290-123F-4565-9164-39C4925E467B": "Downloads",
            "4BD8D571-6D19-48D3-BE97-422220080E43": "Music",
            "33E28130-4E1E-4676-835A-98395C3BC3BB": "Pictures",
            "18989B1D-99B5-455B-841C-AB7C74E4DDFC": "Videos",
            "1AC14E77-02E7-4E5D-B744-2EB1AE5198B7": "System",
            "F38BF504-1D43-42F2-9305-67DE0B28FC23": "Windows",
            "905E63B6-C1BF-494E-B29C-65B732D3D21A": "Program Files",
            "6D809377-6AF0-444B-8957-A3773F02200E": "Program Files (x86)",
            "5E6C858F-0E22-4760-9AFE-EA3317B67173": "User Profile",
            "F1B32785-6FBA-4FCF-9D55-7B8E7F157091": "Local AppData",
            "3EB685DB-65F9-4CF6-A03A-E3EF65729F3D": "Roaming AppData",
            "A4115719-D62E-491D-AA7C-E74B8BE3B067": "Start Menu",
            "B97D20BB-F46A-4C97-BA10-5E3608430854": "Startup",
            "AE50C081-EBD2-438A-8655-8A092E34987A": "Recent",
            "8983036C-27C0-404B-8F08-102D10DCFD74": "SendTo",
            "AB5FB87B-7CE2-4F83-915D-550846C9537B": "RecycleBin"
        }

        return known_folders.get(guid_str.upper(), "Unknown Known Folder")

    def _parse_vista_idlist_data_block(self, data):
        """Parse VistaAndAboveIDListDataBlock (section 2.5.11) - variable size"""
        if len(data) < 2:
            return {'error': 'Insufficient data'}

        # Parse IDList structure
        parsed_items = []
        offset = 0

        while offset < len(data) - 2:
            item_size = int.from_bytes(data[offset:offset + 2], 'little')
            if item_size == 0:
                break

            if offset + item_size > len(data):
                break

            item_data = data[offset + 2:offset + item_size]
            parsed_items.append(
                {
                    'size': item_size,
                    'data_hex': item_data.hex()
                })
            offset += item_size

        return {
            'idlist_items': parsed_items,
            'item_count': len(parsed_items)
        }

    def _format_guid(self, guid_bytes):
        """Format 16 bytes as GUID string"""
        if len(guid_bytes) != 16:
            return "Invalid GUID"

        d1 = int.from_bytes(guid_bytes[0:4], 'little')
        d2 = int.from_bytes(guid_bytes[4:6], 'little')
        d3 = int.from_bytes(guid_bytes[6:8], 'little')
        d4 = guid_bytes[8:10].hex().upper()
        d5 = guid_bytes[10:16].hex().upper()

        return f"{d1:08X}-{d2:04X}-{d3:04X}-{d4}-{d5}"

    def _get_block_type_name(self, signature):
        """Map block signature to name (section 2.5)"""
        block_types = {
            0xA0000001: "EnvironmentVariableDataBlock",
            0xA0000002: "ConsoleDataBlock",
            0xA0000003: "TrackerDataBlock",
            0xA0000004: "ConsoleFEDataBlock",
            0xA0000005: "SpecialFolderDataBlock",
            0xA0000006: "DarwinDataBlock",
            0xA0000007: "IconEnvironmentDataBlock",
            0xA0000008: "ShimDataBlock",
            0xA0000009: "PropertyStoreDataBlock",
            0xA000000B: "KnownFolderDataBlock",
            0xA000000C: "VistaAndAboveIDListDataBlock"
        }
        return block_types.get(signature, f"Unknown (0x{signature:08X})")

    def print_lnk_results(self, data=None, indent=0, prefix=""):
        """Print results in a tree format"""
        if data is None:
            data = self.__dict__

        # Skip internal attributes
        skip_attrs = {'lnk_file', 'buffer', 'link_info_start', 'id_list_size'}

        for key, value in data.items():
            if key in skip_attrs:
                continue

            display_key = key.replace('_', ' ').title()

            if isinstance(value, dict):
                print(f"{' ' * indent}{prefix}▸ {display_key}:")
                self.print_lnk_results(value, indent + 2, prefix + "  ")
            elif isinstance(value, list):
                print(f"{' ' * indent}{prefix}▸ {display_key}: ({len(value)} items)")
                for i, item in enumerate(value):
                    if isinstance(item, dict):
                        print(f"{' ' * (indent + 2)}{prefix}  [{i}]:")
                        self.print_lnk_results(item, indent + 4, prefix + "    ")
                    else:
                        print(f"{' ' * (indent + 2)}{prefix}  [{i}]: {repr(item)}")
            elif value is not None and value != "":
                print(f"{' ' * indent}{prefix}▸ {display_key}: {repr(value)}")


# Example usage
if __name__ == "__main__":
    try:
        lnk = ToolboxLnk(sys.argv[1])
    except FileNotFoundError:
        print("Please provide a valid .lnk file path")
    except ValueError as e:
        print(f"Error: {e}")