
typedef struct tcptrace_working_file {
    pread_f *reader_function;
} tcptrace_working_file;

int tcptrace_load_file(char *filename, tcptrace_working_file *working_file);

