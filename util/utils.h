void safer_free(void *, size_t);
void write_file(FILE *, void *, size_t, char *); 
void get_keys(unsigned char *, unsigned char *, FILE *, FILE *);
void read_infile(FILE *, unsigned char *, unsigned long long);
unsigned long long get_size(FILE *);
