import sys
import datetime
import struct

def hexread(file, offset, length):
    file.seek(offset)
    return struct.unpack('<I', file.read(length))[0]

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python peinfo.py <game_code> <dll_path>")
    else:
        game_code = sys.argv[1]
        dll_path = sys.argv[2]
        try:
            with open(dll_path, 'rb') as file:
                # Read DOS header to get PE header offset
                pe_header_offset = hexread(file, 0x3C, 4)

                # Check for "PE\0\0" signature
                file.seek(pe_header_offset)
                if file.read(4) != b'PE\0\0':
                    raise ValueError(f"File '{dll_path}' is not a valid PE file.")

                # Read TimeDateStamp
                timestamp_offset = pe_header_offset + 8
                timestamp = hexread(file, timestamp_offset, 4)
                readable_timestamp = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')

                # Read AddressOfEntryPoint
                optional_header_offset = pe_header_offset + 24
                entry_point_offset = optional_header_offset + 16
                entry_point = hexread(file, entry_point_offset, 4)

                # Concatenate GameCode, TimeDateStamp, and AddressOfEntryPoint
                identifier = f"{game_code.upper()}-{timestamp:x}_{entry_point:x}"

                # Output results
                print(f"TimeDateStamp: {readable_timestamp} (unix:{timestamp}) (hex:0x{timestamp:08X}) (offset:0x{timestamp_offset:08X})")
                print(f"AddressOfEntryPoint: 0x{entry_point:08X} (offset:0x{entry_point_offset:08X})")
                print(f"PE Identifier: {identifier}")
                print(f"JSON File Name: {identifier}.json")

        except FileNotFoundError:
            print(f"Error: File '{dll_path}' not found.")
        except ValueError as ve:
            print(f"Error: {ve}")
        except Exception as e:
            print(f"Error: {str(e)}")