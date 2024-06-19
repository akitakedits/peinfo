import pefile
import sys
import datetime

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python peinfo.py <game_code> <dll_path>")
    else:
        # Define human-readable variables for arguments
        game_code = sys.argv[1]
        dll_path = sys.argv[2]
        try:
            # Load dll and get PE & Optional headers
            pe = pefile.PE(dll_path)
            pe_header_offset = pe.DOS_HEADER.e_lfanew
            optional_header_offset = pe_header_offset + 24  # OptionalHeader follows PE header which is 24 bytes

            # Get TimeDateStamp and its offset
            timestamp = pe.FILE_HEADER.TimeDateStamp
            readable_timestamp = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            timestamp_offset = pe_header_offset + 8  # FileHeader is at offset 8 within PE header

            # Get AddressOfEntryPoint and its offset
            entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_point_offset = optional_header_offset + 16  # AddressOfEntryPoint is at offset 16 within OptionalHeader

            # Concatenate Model, TimeDateStamp and AddressOfEntryPoint
            identifier = f"{game_code.upper()}-{timestamp:x}_{entry_point:x}"

            # Output the results
            print(f"TimeDateStamp: {readable_timestamp} (unix:{timestamp}) (hex:0x{timestamp:08X}) (offset:0x{timestamp_offset:08X})")
            print(f"AddressOfEntryPoint: 0x{entry_point:08X} (offset:0x{entry_point_offset:08X})")
            print(f"PE Identifier: {identifier}")
            print(f"JSON File Name: {identifier}.json")
        except FileNotFoundError:
            print(f"Error: File '{dll_path}' not found.")
        except pefile.PEFormatError:
            print(f"Error: File '{dll_path}' is not a valid PE file.")
        except Exception as e:
            print(f"Error: {str(e)}")