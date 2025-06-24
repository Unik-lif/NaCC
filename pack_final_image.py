import struct
import sys
import os

AGENT_MAGIC = 0xA6E17C0D
VERSION = 1
LOAD_ADDR = 0x180000000

# 25 MB for the image
FIX_SIZE = 25 * 1024 * 1024 

def align_up(val, align):
    return (val + align - 1) & ~(align - 1)

def main(image_path, agent_path, output_path):
    with open(image_path, "rb") as f:
        linux = f.read()
    with open(agent_path, "rb") as f:
        agent = f.read()

    image_size = len(linux)
    agent_offset = align_up(image_size, 64)
    agent_size = len(agent)


    footer = struct.pack(
        "<IIQQQ32s",
        AGENT_MAGIC,
        VERSION,
        agent_offset,
        agent_size,
        LOAD_ADDR,
        b"\x00" * 32
    )

    footer_size = struct.calcsize("<IIQQQ32s")
    occupied_size = align_up(agent_offset + agent_size, 64) + footer_size
    
    if occupied_size > FIX_SIZE:
        print(f"Error: Final image size {occupied_size} exceeds fixed size {FIX_SIZE}.")
        sys.exit(1)
    

    with open(output_path, "wb") as out:
        out.write(linux)
        out.write(b"\x00" * (agent_offset - len(linux)))  # Padding
        out.write(agent)
        current_pos = agent_offset + len(agent)
        footer_pos = FIX_SIZE - footer_size
        out.write(b"\x00" * (footer_pos - current_pos))
        out.write(footer)

    print(f"Generated final image with:")
    print(f"  Linux Size      : {len(linux)} bytes")
    print(f"  Agent Offset    : {hex(agent_offset)}")
    print(f"  Agent Size      : {hex(agent_size)}")
    print(f"  Load Addr       : {hex(LOAD_ADDR)}")
    print(f"  Footer Offset   : {hex(FIX_SIZE - footer_size)}")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 pack_final_image.py <linux_image> <agent_bin> <output_bin>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2], sys.argv[3])
