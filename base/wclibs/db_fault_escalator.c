

#include <unistd.h>
#include <string.h>     /* For the real memset prototype.  */
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <dirent.h>

#include <sys/socket.h>
#include <sys/uio.h>

#include <sys/types.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/stat.h>

#define __USE_GNU
#include <dlfcn.h>

struct test_process_info {
    int initialized;
    int afl_id;
    int port;
    int reqr_process_id;
    int process_id;
    char error_type[20]; /* SQL, Command */
    char error_msg[100];
    bool capture;
};


void print_repr(FILE *fp, unsigned char *cptr, size_t len);
void error_report(unsigned char *cptr, size_t len);

static ssize_t (*real_write)(int fd, const void *buf, size_t count) = NULL;
static ssize_t (*real_writev)(int fd, const struct iovec *iov, int iovcnt) = NULL;
static const char *fault_log_path = "/tmp/witcher_fault_escalator.log";
static char stderr_path_cache[PATH_MAX] = {0};

void refresh_stderr_path(void){
  char linkpath[64];
  char target[PATH_MAX];
  snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/2");
  ssize_t n = readlink(linkpath, target, sizeof(target) - 1);
  if (n > 0){
    target[n] = '\0';
    if (strcmp(stderr_path_cache, target) != 0){
      strncpy(stderr_path_cache, target, sizeof(stderr_path_cache) - 1);
      stderr_path_cache[sizeof(stderr_path_cache) - 1] = '\0';
    }
  }
}

bool is_shell_error_line(const char *line){
  if (!line){
    return false;
  }
  if (strstr(line, "sh:") || strstr(line, "bash:") || strstr(line, "dash:") || strstr(line, "ash:")){
    return true;
  }
  if (strstr(line, "command not found")){
    return true;
  }
  if (strstr(line, "syntax error") || strstr(line, "Syntax error")){
    return true;
  }
  if (strstr(line, "unexpected token") || strstr(line, "Unexpected token")){
    return true;
  }
  if (strstr(line, "not found")){
    return true;
  }
  if (strstr(line, "unterminated") || strstr(line, "Unterminated")){
    return true;
  }
  return false;
}

bool is_benign_shell_error(const char *line){
  if (!line){
    return false;
  }
  if (strstr(line, "Permission denied") || strstr(line, "permission denied")){
    return true;
  }
  if (strstr(line, "No such file or directory") || strstr(line, "no such file or directory")){
    return true;
  }
  if (strstr(line, "Operation not permitted") || strstr(line, "operation not permitted")){
    return true;
  }
  if (strstr(line, "Read-only file system") || strstr(line, "read-only file system")){
    return true;
  }
  if (strstr(line, "Is a directory") || strstr(line, "is a directory")){
    return true;
  }
  if (strstr(line, "Not a directory") || strstr(line, "not a directory")){
    return true;
  }
  if (strstr(line, "File exists") || strstr(line, "file exists")){
    return true;
  }
  if (strstr(line, "Invalid argument") || strstr(line, "invalid argument")){
    return true;
  }
  if (strstr(line, "cannot open") || strstr(line, "Cannot open")){
    return true;
  }
  return false;
}

bool is_fuzz_shell_error(const char *line){
  if (!line){
    return false;
  }
  if (strstr(line, " not found") || strstr(line, ": not found")){
    const char *has_shell_prefix = strstr(line, "sh:") || strstr(line, "bash:") || strstr(line, "dash:") || strstr(line, "ash:");
    if (has_shell_prefix){
      const char *nf = strstr(line, " not found");
      if (!nf){
        nf = strstr(line, ": not found");
      }
      if (nf){
        const char *last_colon = NULL;
        for (const char *p = line; p < nf; p++){
          if (*p == ':'){
            last_colon = p;
          }
        }
        if (last_colon){
          const char *prev_colon = NULL;
          for (const char *p = line; p < last_colon; p++){
            if (*p == ':'){
              prev_colon = p;
            }
          }
          if (prev_colon){
            const char *tok_start = prev_colon + 1;
            while (*tok_start && isspace((unsigned char)*tok_start)){
              tok_start++;
            }
            const char *tok_end = last_colon;
            while (tok_end > tok_start && isspace((unsigned char)*(tok_end - 1))){
              tok_end--;
            }
            size_t tok_len = (size_t)(tok_end - tok_start);
            if (tok_len == 1 && !isalnum((unsigned char)tok_start[0])){
              return true;
            }
            bool has_nonword = false;
            for (size_t i = 0; i < tok_len; i++){
              unsigned char c = (unsigned char)tok_start[i];
              if (!(isalnum(c) || c == '_' || c == '-' || c == '.')){
                has_nonword = true;
                break;
              }
            }
            if (tok_len > 0 && tok_len <= 3 && has_nonword){
              return true;
            }
          }
        }
      }
    }
  }
  if (strstr(line, "Syntax error") || strstr(line, "syntax error")){
    return true;
  }
  if (strstr(line, "unexpected token") || strstr(line, "Unexpected token")){
    return true;
  }
  if (strstr(line, "EOF") || strstr(line, "eof")){
    return true;
  }
  if (strstr(line, "unterminated") || strstr(line, "Unterminated")){
    return true;
  }
  if (strstr(line, "command not found")){
    return true;
  }
  if (strstr(line, "bad substitution") || strstr(line, "Bad substitution")){
    return true;
  }
  if (strstr(line, "ambiguous redirect") || strstr(line, "Ambiguous redirect")){
    return true;
  }
  if (strstr(line, "illegal option") || strstr(line, "Illegal option")){
    return true;
  }
  if (strstr(line, "invalid option") || strstr(line, "Invalid option")){
    return true;
  }
  if (strstr(line, "bad number") || strstr(line, "Bad number")){
    return true;
  }
  if (strstr(line, "unexpected") || strstr(line, "Unexpected")){
    return true;
  }
  return false;
}

void log_shell_errors_from_stderr(void){
  static long last_pos = 0;
  if (stderr_path_cache[0] == '\0'){
    return;
  }
  FILE *fp = fopen(stderr_path_cache, "r");
  if (!fp){
    return;
  }
  if (fseek(fp, 0, SEEK_END) != 0){
    fclose(fp);
    return;
  }
  long size = ftell(fp);
  if (size < 0){
    fclose(fp);
    return;
  }
  if (size < last_pos){
    last_pos = 0;
  }
  long max_read = 8192;
  long read_start = size > max_read ? size - max_read : 0;
  if (read_start < last_pos){
    read_start = last_pos;
  }
  if (fseek(fp, read_start, SEEK_SET) != 0){
    fclose(fp);
    return;
  }
  char line[1024];
  while (fgets(line, sizeof(line), fp)){
    if (is_shell_error_line(line) && !is_benign_shell_error(line) && is_fuzz_shell_error(line)){
      error_report((unsigned char *)line, strlen(line));
    }
  }
  last_pos = ftell(fp);
  fclose(fp);
}

__attribute__((constructor))
void init_fault_escalator(void){
  refresh_stderr_path();
  log_shell_errors_from_stderr();
}

__attribute__((destructor))
void fini_fault_escalator(void){
  refresh_stderr_path();
  log_shell_errors_from_stderr();
}

ssize_t write(int fd, const void *buf, size_t count){
  real_write = dlsym(RTLD_NEXT, "write");
  if (buf && count > 0 && fd == 2){
    refresh_stderr_path();
    log_shell_errors_from_stderr();
  }
  return real_write(fd, buf, count);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt){
  real_writev = dlsym(RTLD_NEXT, "writev");
  if (iov && iovcnt > 0 && fd == 2){
    refresh_stderr_path();
    log_shell_errors_from_stderr();
  }
  return real_writev(fd, iov, iovcnt);
}

void print_repr(FILE *fp, unsigned char *cptr, size_t len){
    for (int lp=0; lp < len; lp++){
        if (cptr[lp]>= 0x20 && cptr[lp] < 0x7f) {
            fprintf(fp, "%c",cptr[lp]);
        } else {
            fprintf(fp, "\\x%02x",cptr[lp]);
        }
    }
}

void send_signal(int strictval){
    int pid = 0;
    struct test_process_info *afl_info = NULL;
    printf("FOUND STRICT=%d\n", strictval);
    if (getenv("AFL_META_INFO_ID")){
        // clean up last shared memory area
        int mem_key = atoi(getenv("AFL_META_INFO_ID"));
        int shm_id = shmget(mem_key , sizeof(struct test_process_info), 0666);
        fprintf(stderr, "\033[36m [Witcher] who dat %d %d !!!\033[0m\n", mem_key, shm_id);
        if (shm_id  >= 0 ) {
            afl_info = (struct test_process_info *) shmat(shm_id, NULL, 0);  /* attach */
            if (afl_info && afl_info->reqr_process_id){

                pid = afl_info->reqr_process_id;
                fprintf(stderr, "pid=%d ", pid);
            }
        }
        fprintf(stderr, "\n");
    }
    if (pid > 0){
        strcpy(afl_info->error_type,"SQL");
        fprintf(stderr, "\033[36m [Witcher] sending SEGSEGV to %d %d %d !!!\033[0m\n", afl_info->reqr_process_id, afl_info->process_id, getpid());
        kill(pid, SIGSEGV);
    } else{
        if (strictval == 1 || strictval == 2){
            printf("FOUND STRICT=%s, RAISING SIGSEGV\n", strictval);
            raise(SIGSEGV);
        }  else if (strictval == 3 || strictval == 4){
            printf("FOUND STRICT=%s, RAISING SIGSEGV\n", strictval);
            raise(SIGSEGV);
        }
    }
}

void error_report(unsigned char *cptr, size_t len){
    char* strict = getenv("STRICT");
    if (! strict){
        char *fname = "/tmp/witcher.env";
        if( access( fname, R_OK ) == 0 ) {
            FILE *envf = fopen(fname,"r");
            char val[257], ch;
            int charindex = 0;

            if (envf){
                while((ch = fgetc(envf)) != EOF && charindex < 256) {
                    val[charindex] = ch;
                    charindex++;
                }
                if (strstr(val, "STRICT")){
                    strict = val+7;
                }

            }
        }
    }
    if (strict){
        FILE *lfp = fopen(fault_log_path, "a");
        if (lfp){
            fprintf(lfp, "[crash] strict=%s len=%zu\n", strict, len);
            print_repr(lfp, cptr, len);
            fprintf(lfp, "\n");
            fclose(lfp);
        }
        char* httpreqr_pidfile = "/tmp/httpreqr.pid";
        int kill_res = 0;
        FILE *fco = NULL;
        char *alt_fconfn = "/tmp/witcher.log";
        if( access( alt_fconfn, F_OK ) == 0 && access( alt_fconfn, W_OK ) == 0 ) {
            fco = fopen(alt_fconfn, "a");
        }
        if (fco) {
            fprintf(fco, "checking for pid file\n");
            fflush(fco);
        }
        if( access( httpreqr_pidfile, F_OK ) == 0) {
            int httpreqr_pid = 0;
            FILE *pidfile = fopen(httpreqr_pidfile, "r");
            fscanf (pidfile, "%d", &httpreqr_pid);
            fclose(pidfile);
            if (fco) {
                fprintf(fco, "\033[36m[Witcher-dash] sending SIGSEGV to reqr_pid=%d  \033[0m\n", httpreqr_pid );
            }
            if (httpreqr_pid != 0){
                kill_res = kill(httpreqr_pid, SIGSEGV);
            }
            if (fco) {
                fprintf(fco, "\033[36m kill_res = %d  \033[0m\n", kill_res);
            }
        } else {
            fprintf(stderr, "Error encountered, strict=%s\n", strict);
            int strictval = atoi(strict);
            send_signal(strictval);
       }
    } else {
        printf("RECV ERROR FOUND!!!!! But not escalating... STRICT=%s \n", strict);
    }
    fprintf(stderr, "[*] Found error message  \n");
    print_repr(stderr, cptr, len);
    fprintf(stderr, "\n");
}

bool buffer_contains_ci(const unsigned char *buf, size_t len, const char *pattern){
  size_t pat_len = strlen(pattern);
  if (pat_len == 0 || len < pat_len){
    return false;
  }
  for (size_t i = 0; i + pat_len <= len; i++){
    size_t j = 0;
    for (; j < pat_len; j++){
      unsigned char c = buf[i + j];
      if (tolower(c) != tolower((unsigned char)pattern[j])){
        break;
      }
    }
    if (j == pat_len){
      return true;
    }
  }
  return false;
}

bool shell_error_injection_like(const unsigned char *buf, size_t len){
  bool has_shell_prefix = buffer_contains_ci(buf, len, "sh:") || buffer_contains_ci(buf, len, "bash:") || buffer_contains_ci(buf, len, "dash:") || buffer_contains_ci(buf, len, "ash:");
  if (buffer_contains_ci(buf, len, "command not found")){
    return true;
  }
  if (buffer_contains_ci(buf, len, "syntax error")){
    return true;
  }
  if (buffer_contains_ci(buf, len, "unexpected token")){
    return true;
  }
  if (buffer_contains_ci(buf, len, "not found") && has_shell_prefix){
    return true;
  }
  return false;
}
