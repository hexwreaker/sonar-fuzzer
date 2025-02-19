import csv
import hashlib
import time
import os
import sys
from capstone import *
import lief
from lief import parse

def calculate_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_sprf_csv(binary_path, output_csv):
    # Parse the binary using LIEF
    binary = parse(binary_path)

    # Extract target information
    target_filename = os.path.basename(binary_path)
    architecture = binary.header.machine_type
    mode_bits = binary.header.identity_class
    target_sha256_sum = calculate_sha256(binary_path)

    # Extract probes context
    generation_rule = "jmp;call"  # You can customize this rule
    text_section = binary.get_section(".text")
    start_text_seg = text_section.virtual_address
    text_size = text_section.size
    end_text_seg = start_text_seg + text_size

    if architecture == lief.ELF.ARCH.I386 or architecture == lief.ELF.ARCH.X86_64:
        architecture = "x86"
        cs_arch = CS_ARCH_X86
        if binary.header.identity_class == lief.ELF.Header.CLASS.ELF32:
            mode = CS_MODE_32    
            mode_bits = 32    
        else:
            mode = CS_MODE_64    
            mode_bits = 64    

    else:
        raise ValueError("Architecture non supportée par le profilage")

    # Extract probes list (example: addresses of instructions)
    md = Cs(cs_arch, mode)
    instructions = md.disasm(text_section.content, start_text_seg)
    # Collecter les instructions jmp et call
    probes = []
    for instr in instructions:
        if instr.mnemonic in ["jmp", "call"]:
            probes.append(hex(instr.address))

    # Create the SPRF file structure
    sprf_file = {
        "magic_number": "SPRF",
        "date_of_creation": int(time.time()),
        "date_of_last_modification": int(time.time()),
        "target_filename": target_filename,
        "architecture": architecture,
        "mode_bits": mode_bits,
        "target_sha256_sum": target_sha256_sum,
        "generation_rule": generation_rule,
        "start_text_seg": hex(start_text_seg),
        "end_text_seg": hex(end_text_seg),
        "probes": probes,
        "footer": "gloups"
    }

    # Write the SPRF file to a CSV
    with open(output_csv, "w", newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        # Write header
        csvwriter.writerow([sprf_file["magic_number"], sprf_file["date_of_creation"], sprf_file["date_of_last_modification"]])
        # Write target information
        csvwriter.writerow([sprf_file["target_filename"], sprf_file["architecture"], sprf_file["mode_bits"], sprf_file["target_sha256_sum"]])
        # Write probes context
        csvwriter.writerow([sprf_file["generation_rule"], sprf_file["start_text_seg"], sprf_file["end_text_seg"]])
        # Write probes list
        csvwriter.writerow(sprf_file["probes"])
        # Write footer
        csvwriter.writerow([sprf_file["footer"]])

def main():
    if len(sys.argv) != 3:
        print(f"Usage : {sys.argv[0]} <target> <output>")
        exit(-1)
    print(f"Target : {sys.argv[1]}\nOutput : {sys.argv[2]}")
    # Example usage
    binary_path = sys.argv[1]
    output_csv = sys.argv[2]
    generate_sprf_csv(binary_path, output_csv)
main()
