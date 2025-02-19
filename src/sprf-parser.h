//
// A "Sonar Profile" file (.sprf) is a CSV file that contains informations about a target binary and how the Sonar fuzzer can fuzz it (probes list).
//
//  Format (csv) :
//      |       records         |       values...
//      |-----------------------|---------------------------------------------------------------------
//      |   sonar file header   |   magic_number,date_of_creation,date_of_last_modification,sha256_sum 
//      |  target informations  |   filename,architecture,mode_bits,sha256_sum
//      |    probes context     |   generation_rule(a rule, instructions, etc.),start_text_segment,end_text_segment
//      |    probes list        |   address1,address2,address3,address4,address5,address6
//      |   sonar file footer   |   gloups
//
#ifndef SPRF_FILE_H
#define SPRF_FILE_H

#include <stdint.h>
#include <time.h>

struct sprf_file {
    // header
    char magic_number[4];
    time_t date_of_creation;
    time_t date_of_last_modification;
    // target informations
    char *target_filename;
    char *architecture;
    int mode_bits;
    char target_sha256_sum[32];
    // probes context
    char *generation_rule;
    uint64_t start_text_seg;
    uint64_t end_text_seg;
    // probes list
    uint64_t *probes;
    size_t probes_count;
    // footer
    char footer[6];
};

char* parse_sprf_file_header(struct sprf_file* sprfile, char* fbytes);
char* parse_sprf_target_informations(struct sprf_file* sprfile, char* fbytes);
char* parse_sprf_probes_context(struct sprf_file* sprfile, char* fbytes);
char* parse_sprf_probes_list(struct sprf_file* sprfile, char* fbytes);
char* parse_sprf_footer(struct sprf_file* sprfile, char* fbytes);

void print_sprf_file_header(struct sprf_file* sprfile);
void print_sprf_target_informations(struct sprf_file* sprfile); 
void print_sprf_probes_context(struct sprf_file* sprfile);
void print_sprf_probes_list(struct sprf_file* sprfile);
void print_sprf_footer(struct sprf_file* sprfile);
void print_sprf_file(struct sprf_file* sprfile);

struct sprf_file* load_sprf_file(char* filename);
int unload_sprf_file(struct sprf_file* sprfile);

#endif // SPRF_FILE_H
