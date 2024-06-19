# peinfo

## About

Short python script to generate a game dll's [PE Identifier](https://github.com/spice2x/spice2x.github.io/wiki/patches.json-specification#pe-identifier) for [Spice2x patching](https://two-torial.xyz/extras/patchsp2x/).  
This lets you know what a json file should be named in order to be loaded by spicecfg's [Importing Patches from URL](https://github.com/spice2x/spice2x.github.io/wiki/Patching-DLLs-(hex-edits)#importing-patches-from-a-url) feature.

## Requirements

- Install **python 3.6 or newer** *(according to [vermin](https://github.com/netromdk/vermin))*
- Clone the repo and go to its root directory `git clone https://github.com/akitakedits/peinfo.git && cd peinfo`

## Usage

`python peinfo.py <game_code> <dll_path>`

### Arguments

- `game_code` - The game code (KFC, LDJ, etc..) corresponding to your dll file, not case sensitive.
- `dll_path` - The path to your dll. If contained within the same directory it can simply be the dll's file name.

### Example

```
> python peinfo.py ldj bm2dx.dll
TimeDateStamp: 2024-04-25 07:27:03 (unix:1714030023) (hex:0x662A05C7) (offset:0x00000180)
AddressOfEntryPoint: 0x00A5BF9C (offset:0x000001A0)
PE Identifier: LDJ-662a05c7_a5bf9c
JSON File Name: LDJ-662a05c7_a5bf9c.json
```
