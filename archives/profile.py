# Un fichier "profil" d'un binaire cible doit respecter le format suivant :
# 
#   str     |       "{ARCH}\n"
#   str     |       "{MODE}\n"                  MODE = "64" ou "32"
#   str     |       "{BASE_ADDR b16}\n"         l'adresse de base de la section .text en hexa
#   str     |       "{LAST_ADDR b16}\n"         l'adresse de fin de la section .text en hexa
#   str     |       "{INSTRUCTIONS_NAMES}\n"    informatinos sur les instruction ciblées par le "profiling"
#   str     |       "{NUMBER_POI b10}\n"        le nombre d'adresses correspondant aux points d'intérêts ciblés en décimal
#   str     |       "{POIs b16}\n"              la liste des points d'intérêts ciblés : adresse en hexa.
# 

import lief
from capstone import *
import os

def generate_profile(binary_path, output_path):
    # Charger le binaire ELF
    binary = lief.parse(binary_path)
    if not binary or not binary.has_section(".text"):
        raise ValueError("Le binaire ne contient pas de section .text ou n'est pas valide")

    # Obtenir la section .text
    text_section = binary.get_section(".text")
    base_addr = text_section.virtual_address
    text_size = text_section.size
    last_addr = base_addr + text_size

    # Charger les instructions avec Capstone
    print(binary.header.machine_type)
    arch = binary.header.machine_type
    if arch == lief.ELF.ARCH.I386:
        cs_arch = CS_ARCH_X86
        mode = CS_MODE_32 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF32 else CS_MODE_64
    else:
        raise ValueError("Architecture non supportée par le profilage")

    md = Cs(cs_arch, mode)
    instructions = md.disasm(text_section.content, base_addr)

    # Collecter les instructions jmp et call
    pois = []
    for instr in instructions:
        if instr.mnemonic in ["jmp", "call"]:
            pois.append(instr.address)

    # Préparer les données pour le fichier de profil
    arch_str = "x86"
    mode_str = "64" if mode == CS_MODE_64 else "32"
    instructions_names = "jmp,call"
    number_pois = len(pois)
    pois_str = "\n".join(f"{addr:016x}" for addr in pois)

    # Créer le fichier de profil
    with open(output_path, "w") as f:
        f.write(f"{arch_str}\n")
        f.write(f"{mode_str}\n")
        f.write(f"{base_addr:016x}\n")
        f.write(f"{last_addr:016x}\n")
        f.write(f"{instructions_names}\n")
        f.write(f"{number_pois}\n")
        f.write(f"{pois_str}\n")

    print(f"Profil généré dans le fichier : {output_path}")


if __name__ == "__main__":
    # Chemin du binaire ELF
    binary_path = "./ch17"
    output_path = "profil.txt"

    # Vérifier si le fichier existe
    if not os.path.isfile(binary_path):
        print(f"Erreur : le fichier {binary_path} n'existe pas.")
    else:
        try:
            generate_profile(binary_path, output_path)
        except Exception as e:
            print(f"Erreur : {e}")