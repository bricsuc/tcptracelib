
typedef struct tcptrace_working_file {
    pread_f *reader_function;
    u_long filesize;
    Bool is_stdin;
} tcptrace_working_file;

typedef enum {
    TCPTRACE_LOAD_SUCCESS,
    TCPTRACE_WONT_UNCOMPRESS,
    TCPTRACE_CANT_STAT,
    TCPTRACE_UNKNOWN_FORMAT,
    TCPTRACE_CANT_OPEN
} tcptrace_load_status_t;

tcptrace_load_status_t tcptrace_load_file(char *filename, tcptrace_working_file *working_file);
void tcptrace_show_formats(void);

