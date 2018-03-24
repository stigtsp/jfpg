#include "hdr.h"

void write_file(FILE *, void *, size_t, char *); 
void get_keys(unsigned char *, unsigned char *, FILE *, FILE *);
void read_infile(FILE *, unsigned char *, unsigned long long);
void decrypt_key(unsigned char *, FILE *);
void read_hdr(struct hdr *, FILE *);
void write_enc(FILE *, struct hdr *, unsigned char *, char *); 
off_t get_size(FILE *);
