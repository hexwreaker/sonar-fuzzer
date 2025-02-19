//
// A "Sonar Profile" file (.sprf) is a CSV file that contains informations about a target binary and how the Sonar fuzzer can fuzz it (probes list).
//
//  Format (csv) :
//      |       records         |       values...
//      |-----------------------|---------------------------------------------------------------------
//      |   sonar file header   |   magic_number,date_of_creation,date_of_last_modification 
//      |  target informations  |   filename,architecture,mode_bits,sha256_sum
//      |    probes context     |   generation_rule(a rule, instructions, etc.),start_text_segment,end_text_segment
//      |    probes list        |   address1,address2,address3,address4,address5,address6
//      |   sonar file footer   |   gloups
//
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include "util.h"
#include "sprf-parser.h" // Include the header file

int debug_parser = 1;

char* parse_sprf_file_header(struct sprf_file* sprfile, char* file_bytes) {
    memcpy(sprfile->magic_number, file_bytes, 4);
    if (strncasecmp(sprfile->magic_number, "sprf", 4) != 0) {
        fprintf(stderr, BOLDRED "[!] parse file error : Invalid magic number\n" RESET);
        return 0;
    }
    file_bytes += 5;
    
    // Convert date_of_creation from decimal string to time_t
    char *endptr;
    sprfile->date_of_creation = (time_t)strtoull(file_bytes, &endptr, 10);
    file_bytes = endptr+1;

    // Convert date_of_last_modification from decimal string to time_t
    sprfile->date_of_last_modification = (time_t)strtoull(file_bytes, &endptr, 10);
    file_bytes = endptr+1;

    return file_bytes+1;
}

char* parse_sprf_target_informations(struct sprf_file* sprfile, char* file_bytes) {
    size_t filename_len = strchr(file_bytes, ',')-file_bytes;
    sprfile->target_filename = malloc(filename_len+1);
    if (!sprfile->target_filename) return NULL;
    memcpy(sprfile->target_filename, file_bytes, filename_len);
    sprfile->target_filename[filename_len] = 0;
    file_bytes += filename_len+1;

    size_t arch_len = strchr(file_bytes, ',')-file_bytes;
    sprfile->architecture = malloc(arch_len+1);
    if (!sprfile->architecture) return NULL;
    memcpy(sprfile->architecture, file_bytes, arch_len);
    sprfile->architecture[arch_len] = 0;
    file_bytes += arch_len+1;

    sprfile->mode_bits = strtol(file_bytes, &file_bytes, 10);
    file_bytes += 1;

    memcpy(sprfile->target_sha256_sum, file_bytes, 64);
    file_bytes += 64+2;

    return file_bytes;
}

char* parse_sprf_probes_context(struct sprf_file* sprfile, char* file_bytes) {
    size_t rule_len = strchr(file_bytes, ',')-file_bytes;
    sprfile->generation_rule = malloc(rule_len+1);
    if (!sprfile->generation_rule) return NULL;
    memcpy(sprfile->generation_rule, file_bytes, rule_len);
    sprfile->generation_rule[rule_len] = 0;
    file_bytes += rule_len+1;

    // Convert start_text_seg from hexadecimal string to uint64_t
    sprfile->start_text_seg = (uint64_t)strtoul(file_bytes, &file_bytes, 16);
    file_bytes += 1; // Move past the hex string and the null terminator

    // Convert end_text_seg from hexadecimal string to uint64_t
    sprfile->end_text_seg = (uint64_t)strtoul(file_bytes, &file_bytes, 16);
    file_bytes += 1; // Move past the hex string and the null terminator

    return file_bytes+1;
}

char* parse_sprf_probes_list(struct sprf_file* sprfile, char* fbytes) {
    // Count the number of probes by calculating the number of hexadecimal entries
    size_t probes_count = 0;
    char *cursor = fbytes;

    while (*cursor != '\n') {
        probes_count++;
        while (*cursor != ',' && *cursor != '\n') {
            cursor++;
        }
        if (*cursor == ',') {
            cursor++;
        }
    }

    sprfile->probes = malloc(probes_count * sizeof(uint64_t));
    if (!sprfile->probes) return NULL;

    printf("there are %ld probes\n", probes_count);

    // Convert each hexadecimal string to uint64_t
    cursor = fbytes;
    for (size_t i = 0; i < probes_count; i++) {
        char *endptr;
        sprfile->probes[i] = strtoull(cursor, &endptr, 16);
        cursor = endptr;
        if (*cursor == ',') {
            cursor++;
        }
    }

    sprfile->probes_count = probes_count;

    return cursor+2;
}

char* parse_sprf_footer(struct sprf_file* sprfile, char* file_bytes) {
    memcpy(sprfile->footer, file_bytes, 6);
    if (strncasecmp(sprfile->footer, "gloups", 6) != 0) {
        fprintf(stderr, "Invalid footer\n");
        return NULL;
    }
    return file_bytes+7;
}

void print_sprf_file_header(struct sprf_file* sprfile) {
    printf("Sonar File Header:\n");
    printf("Magic Number: %s\n", sprfile->magic_number);
    struct tm *tm_info;
    char buffer[26];
    // Convert date_of_creation to local time and format it
    tm_info = localtime(&sprfile->date_of_creation);
    strftime(buffer, 26, "%d/%m/%Y", tm_info);
    printf("Date of Creation: %s\n", buffer);
    // Convert date_of_last_modification to local time and format it
    tm_info = localtime(&sprfile->date_of_last_modification);
    strftime(buffer, 26, "%d/%m/%Y", tm_info);
    printf("Date of Last Modification: %s\n", buffer);
}

void print_sprf_target_informations(struct sprf_file* sprfile) {
    printf("Target Informations:\n");
    printf("Filename: %s\n", sprfile->target_filename);
    printf("Architecture: %s\n", sprfile->architecture);
    printf("Mode Bits: %d\n", sprfile->mode_bits);
    printf("SHA256 Sum: %s\n", sprfile->target_sha256_sum);
}

void print_sprf_probes_context(struct sprf_file* sprfile) {
    printf("Probes Context:\n");
    printf("Generation Rule: %s\n", sprfile->generation_rule);
    printf("Start Text Segment: 0x%lx\n", sprfile->start_text_seg);
    printf("End Text Segment: 0x%lx\n", sprfile->end_text_seg);
}

void print_sprf_probes_list(struct sprf_file* sprfile) {
    printf("Probes List:\n");
    for (size_t i = 0; i < sprfile->probes_count; i++) {
        printf("Probe %zu: 0x%lx\n", i, sprfile->probes[i]);
    }
}

void print_sprf_footer(struct sprf_file* sprfile) {
    printf("Sonar File Footer:\n");
    printf("Footer: %s\n", sprfile->footer);
}

void print_sprf_file(struct sprf_file* sprfile) {
    print_sprf_file_header(sprfile);
    print_sprf_target_informations(sprfile);
    print_sprf_probes_context(sprfile);
    print_sprf_probes_list(sprfile);
    print_sprf_footer(sprfile);
}




int unload_sprf_file(struct sprf_file* sprfile) {
    if (sprfile->target_filename) free(sprfile->target_filename);
    if (sprfile->architecture) free(sprfile->architecture);
    if (sprfile->generation_rule) free(sprfile->generation_rule);
    if (sprfile->probes) free(sprfile->probes);
    free(sprfile);
    return 0;
}

struct sprf_file* load_sprf_file(char* filename) {
    if (debug_parser >= 1) { printf(GREEN"[i] parser : start parsing of %s.\n"RESET, filename); }
    
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Failed to open file");
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    char *file_bytes = malloc(file_size);
    if (!file_bytes) {
        fclose(file);
        return NULL;
    }
    if (debug_parser >= 1) { printf(GREEN"[i] parser : %s opened of size %ld.\n"RESET, filename, file_size); }

    fread(file_bytes, 1, file_size, file);
    fclose(file);

    struct sprf_file *sprfile = malloc(sizeof(struct sprf_file));
    if (!sprfile) { free(file_bytes); return NULL; }
    bzero(sprfile, sizeof(struct sprf_file));
    if (debug_parser >= 1) { printf(GREEN"[i] parser : file read.\n"RESET); }

    char *cursor = file_bytes;
    if ((cursor = parse_sprf_file_header(sprfile, cursor)) == 0) goto error;
    if (debug_parser >= 1) { printf(GREEN"[i] parser : header parsed correctly.\n"RESET); }
    if (debug_parser >= 1) { print_sprf_file_header(sprfile); }

    if ((cursor = parse_sprf_target_informations(sprfile, cursor)) == 0) goto error;
    if (debug_parser >= 1) { printf(GREEN"[i] parser : target informations parsed correctly.\n"RESET); }
    if (debug_parser >= 1) { print_sprf_target_informations(sprfile); }

    if ((cursor = parse_sprf_probes_context(sprfile, cursor)) == 0) goto error;
    if (debug_parser >= 1) { printf(GREEN"[i] parser : probes context parsed correctly.\n"RESET); }
    if (debug_parser >= 1) { print_sprf_probes_context(sprfile); }

    if ((cursor = parse_sprf_probes_list(sprfile, cursor)) == 0) goto error;
    if (debug_parser >= 1) { printf(GREEN"[i] parser : probes parsed correctly.\n"RESET); }
    if (debug_parser >= 1) { print_sprf_probes_list(sprfile); }

    if ((cursor = parse_sprf_footer(sprfile, cursor)) == 0) goto error;
    if (debug_parser >= 1) { printf(GREEN"[i] parser : footer parsed correctly.\n"RESET); }
    if (debug_parser >= 1) { print_sprf_footer(sprfile); }

    free(file_bytes);
    return sprfile;

error:
    free(file_bytes);
    unload_sprf_file(sprfile);
    return NULL;
}
