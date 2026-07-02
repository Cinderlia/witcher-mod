

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


int jdbc_error_check(unsigned char *cptr, size_t len);
void print_repr(FILE *fp, unsigned char *cptr, size_t len);
bool pattern_in_bytes(unsigned char *target, int target_len, unsigned char *pattern, int pattern_len);
void mysql_error_check(unsigned char *cptr, size_t len);
void error_report(unsigned char *cptr, size_t len);
void command_error_report(unsigned char *cptr, size_t len);
void error_report_with_type(unsigned char *cptr, size_t len, const char *error_type, const char *missing_strict_msg);
void send_signal(int strictval, const char *error_type);
bool has_non_ascii_bytes(const char *line);
bool token_has_non_ascii(const char *start, size_t len);
void inspect_stream_file(const char *path, bool allow_report);
void inspect_one_line(const char *line, bool allow_report);

static ssize_t (*real_recv)(int sockfd, void *buf, size_t len, int flags) = NULL;
static const char *fault_log_path = "/tmp/witcher_fault_escalator.log";
static char stderr_path_cache[PATH_MAX] = {0};

ssize_t recv(int sockfd, void *buf, size_t len, int flags){
  real_recv = dlsym(RTLD_NEXT, "recv");
  ssize_t results = real_recv(sockfd, buf, len, flags);

  if (buf && results > 0){
    unsigned char *cptr = (unsigned char *)(buf);
    jdbc_error_check(cptr, (size_t)results);
    mysql_error_check(cptr, (size_t)results);
  }

  return results;
}

bool pattern_in_bytes(unsigned char *target, int target_len, unsigned char *pattern, int pattern_len){
  if (target_len <= pattern_len){
      return false;
  }
  for (int i = 0; i < target_len - pattern_len; i++) {
      bool found = true;
      for (int j = 0; j < pattern_len; j++) {

          if (pattern[j] == '.'){
              i++;
              continue;
          } else if (pattern[j] == '~'){
            if (target[i] >= 0x20 && target[i] < 0x7f) {
                while (target[i] >= 0x20 && target[i] < 0x7f) {
                  i++;
                }
                continue;
                found = false;
                break;
            }
          }

          if (target[i] != pattern[j]){
              found = false;
              break;
          }

          i++;
      }
      if (found){
          return true;
      }

  }

  return false;
}

bool has_shell_prefix(const char *line){
  if (!line){
    return false;
  }
  return strstr(line, "sh:") || strstr(line, "bash:") || strstr(line, "dash:") || strstr(line, "ash:");
}

bool has_shell_metachar(const char *line){
  if (!line){
    return false;
  }
  if (strstr(line, "$(") || strstr(line, "${") || strstr(line, "`")){
    return true;
  }
  if (strstr(line, "&&") || strstr(line, "||") || strstr(line, ">>") || strstr(line, "<<")){
    return true;
  }
  if (strstr(line, ";") || strstr(line, "|")){
    return true;
  }
  return false;
}

bool has_non_ascii_bytes(const char *line){
  if (!line){
    return false;
  }
  const unsigned char *p = (const unsigned char *)line;
  while (*p){
    if (*p >= 0x80){
      return true;
    }
    p++;
  }
  return false;
}

bool has_exposed_shell_chars(const char *line){
  if (!line){
    return false;
  }
  if (has_non_ascii_bytes(line)){
    return true;
  }
  if (strstr(line, "'") || strstr(line, "\"") || strstr(line, "`")){
    return true;
  }
  if (strstr(line, "$(") || strstr(line, "${")){
    return true;
  }
  if (strstr(line, "&&") || strstr(line, "||")){
    return true;
  }
  if (strstr(line, ";") || strstr(line, "|") || strstr(line, "<") || strstr(line, ">")){
    return true;
  }
  if (strstr(line, "\\") || strstr(line, "(") || strstr(line, ")")){
    return true;
  }
  return false;
}

bool token_has_non_ascii(const char *start, size_t len){
  if (!start || len == 0){
    return false;
  }
  for (size_t i = 0; i < len; i++){
    if (((const unsigned char *)start)[i] >= 0x80){
      return true;
    }
  }
  return false;
}

bool token_has_shell_metachar(const char *start, size_t len){
  if (!start || len == 0){
    return false;
  }
  for (size_t i = 0; i < len; i++){
    unsigned char c = (unsigned char)start[i];
    if (c == ';' || c == '|' || c == '&' || c == '`' || c == '$' || c == '(' || c == ')' || c == '<' || c == '>'){
      return true;
    }
  }
  return false;
}

bool has_shell_syntax_context(const char *line){
  if (!line){
    return false;
  }
  if (!has_shell_prefix(line)){
    return false;
  }
  if (has_exposed_shell_chars(line) || has_shell_metachar(line)){
    return true;
  }
  if (strstr(line, "unexpected EOF") || strstr(line, "Unexpected EOF")){
    return true;
  }
  if (strstr(line, "end of file unexpected") || strstr(line, "End of file unexpected")){
    return true;
  }
  if (strstr(line, "looking for matching") || strstr(line, "Looking for matching")){
    return true;
  }
  if (strstr(line, "Unterminated quoted string") || strstr(line, "unterminated quoted string")){
    return true;
  }
  return false;
}

bool has_suspicious_option_context(const char *line){
  if (!line){
    return false;
  }
  if (!has_shell_prefix(line)){
    return false;
  }
  if (has_exposed_shell_chars(line) || has_shell_metachar(line)){
    return true;
  }
  const char *marker = strstr(line, "--");
  if (!marker){
    return false;
  }
  marker += 2;
  while (*marker && (isspace((unsigned char)*marker) || *marker == '\'' || *marker == '"' || *marker == '`')){
    marker++;
  }
  if (!*marker){
    return false;
  }
  return !isalnum((unsigned char)*marker);
}

void refresh_stream_path(int fd, char *cache, size_t cache_len){
  char linkpath[64];
  char target[PATH_MAX];
  snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", fd);
  ssize_t n = readlink(linkpath, target, sizeof(target) - 1);
  if (n > 0){
    target[n] = '\0';
    if (strcmp(cache, target) != 0){
      strncpy(cache, target, cache_len - 1);
      cache[cache_len - 1] = '\0';
    }
  }
}

void refresh_stderr_path(void){
  refresh_stream_path(2, stderr_path_cache, sizeof(stderr_path_cache));
}

bool is_shell_error_line(const char *line){
  if (!line){
    return false;
  }
  if (has_shell_prefix(line)){
    return true;
  }
  if (strstr(line, "command not found") && (has_shell_prefix(line) || has_exposed_shell_chars(line))){
    return true;
  }
  if ((strstr(line, "syntax error") || strstr(line, "Syntax error")) && has_shell_syntax_context(line)){
    return true;
  }
  if ((strstr(line, "unexpected token") || strstr(line, "Unexpected token")) && has_shell_syntax_context(line)){
    return true;
  }
  if (strstr(line, "not found") && has_shell_prefix(line)){
    return true;
  }
  if ((strstr(line, "unterminated") || strstr(line, "Unterminated")) && has_shell_syntax_context(line)){
    return true;
  }
  if ((strstr(line, "bad substitution") || strstr(line, "Bad substitution")) && has_shell_syntax_context(line)){
    return true;
  }
  if ((strstr(line, "ambiguous redirect") || strstr(line, "Ambiguous redirect")) && has_shell_syntax_context(line)){
    return true;
  }
  if ((strstr(line, "illegal option") || strstr(line, "Illegal option") ||
       strstr(line, "invalid option") || strstr(line, "Invalid option") ||
       strstr(line, "bad number") || strstr(line, "Bad number")) &&
      has_suspicious_option_context(line)){
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
    if (has_shell_prefix(line)){
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
            if (tok_len > 0 && tok_len <= 64 && token_has_non_ascii(tok_start, tok_len)){
              return true;
            }
            if (tok_len > 0 && tok_len <= 32 && has_nonword && token_has_shell_metachar(tok_start, tok_len)){
              return true;
            }
          }
        }
      }
    }
  }
  if ((strstr(line, "Syntax error") || strstr(line, "syntax error")) && has_shell_syntax_context(line)){
    return true;
  }
  if ((strstr(line, "unexpected token") || strstr(line, "Unexpected token")) && has_shell_syntax_context(line)){
    return true;
  }
  if ((strstr(line, "EOF") || strstr(line, "eof")) && has_shell_syntax_context(line)){
    return true;
  }
  if ((strstr(line, "unterminated") || strstr(line, "Unterminated")) && has_shell_syntax_context(line)){
    return true;
  }
  if (strstr(line, "command not found") && has_shell_prefix(line) && has_exposed_shell_chars(line)){
    return true;
  }
  if ((strstr(line, "bad substitution") || strstr(line, "Bad substitution")) && has_shell_syntax_context(line)){
    return true;
  }
  if ((strstr(line, "ambiguous redirect") || strstr(line, "Ambiguous redirect")) && has_shell_syntax_context(line)){
    return true;
  }
  if ((strstr(line, "illegal option") || strstr(line, "Illegal option")) && has_suspicious_option_context(line)){
    return true;
  }
  if ((strstr(line, "invalid option") || strstr(line, "Invalid option")) && has_suspicious_option_context(line)){
    return true;
  }
  if ((strstr(line, "bad number") || strstr(line, "Bad number")) && has_suspicious_option_context(line)){
    return true;
  }
  return false;
}

void log_shell_errors_from_stderr(void){
  if (stderr_path_cache[0] == '\0'){
    return;
  }
  inspect_stream_file(stderr_path_cache, true);
}

void inspect_stream_file(const char *path, bool allow_report){
  static long last_stderr_pos = 0;
  if (!path || path[0] == '\0'){
    return;
  }
  FILE *fp = fopen(path, "r");
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
  if (size < last_stderr_pos){
    last_stderr_pos = 0;
  }
  long max_read = 8192;
  long read_start = size > max_read ? size - max_read : 0;
  if (read_start < last_stderr_pos){
    read_start = last_stderr_pos;
  }
  if (fseek(fp, read_start, SEEK_SET) != 0){
    fclose(fp);
    return;
  }
  char line[1024];
  while (fgets(line, sizeof(line), fp)){
    inspect_one_line(line, allow_report);
  }
  last_stderr_pos = ftell(fp);
  fclose(fp);
}

void inspect_one_line(const char *line, bool allow_report){
  if (!line){
    return;
  }
  bool level1 = is_shell_error_line(line);
  bool benign = is_benign_shell_error(line);
  bool level3 = is_fuzz_shell_error(line);
  bool hit = level1 && !benign && level3;
  if (hit && allow_report){
    command_error_report((unsigned char *)line, strlen(line));
  }
}

__attribute__((constructor))
void init_fault_escalator(void){
  refresh_stderr_path();
  if (stderr_path_cache[0] != '\0'){
    inspect_stream_file(stderr_path_cache, false);
  }
}

__attribute__((destructor))
void fini_fault_escalator(void){
  refresh_stderr_path();
  log_shell_errors_from_stderr();
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

int jdbc_error_check(unsigned char *cptr, size_t len){
    //\x02\x00\x00\x00,\x00\x00\x00\x17unexpected token: SMITH\x00\x00\x00\x0542581\xff\xff\xea3\x7f
    // \x02\x00\x00\x00(\x00\x00\x00\x13malformed string: '    \x00\x00\x00\x0542584\xff\xff\xea
    unsigned char *jdbc_msg1 = (unsigned char *)"\x02\x00\x00\x00.\x00\x00\x00.~\x00\x00\x00\x05~\xff\xff\xea"; // 18
    unsigned char *jdbc_msg4 = (unsigned char *)"\xff\xff\xea"; // 3

    if (pattern_in_bytes(cptr, (int)len, jdbc_msg4, 3)){
        if (pattern_in_bytes(cptr, (int)len, jdbc_msg1, 18)){
            error_report(cptr, len);
            return 1;
        }
    }
    return 0;
}

void send_signal(int strictval, const char *error_type){
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
        strcpy(afl_info->error_type, error_type ? error_type : "SQL");
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
    error_report_with_type(cptr, len, "SQL", "RECV ERROR FROM DATABASE FOUND!!!!! But not escalating... STRICT=%s \n");
}

void command_error_report(unsigned char *cptr, size_t len){
    error_report_with_type(cptr, len, "COMMAND", "RECV ERROR FOUND!!!!! But not escalating... STRICT=%s \n");
}

void error_report_with_type(unsigned char *cptr, size_t len, const char *error_type, const char *missing_strict_msg){
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
            fprintf(lfp, "[crash] type=%s strict=%s len=%zu\n", error_type ? error_type : "", strict, len);
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
            send_signal(strictval, error_type);
       }
    } else {
        printf(missing_strict_msg, strict);
    }
    fprintf(stderr, "[*] Found error message  \n");
    print_repr(stderr, cptr, len);
    fprintf(stderr, "\n");
}

void mysql_error_check(unsigned char *cptr, size_t len) {

  //printf("!!!!!!!!!!!!!!!!!!! Thank you for using the special RECV --->> !!!!!!!!!!!!!!!!!!!!\n");
  unsigned char *mysql_msg = (unsigned char *)"You have an error i";
  int error_msg_len = strlen((char *)mysql_msg);
  if (pattern_in_bytes(cptr, (int)len, mysql_msg, error_msg_len)){
    error_report(cptr, len);
  }

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
  bool has_prefix = buffer_contains_ci(buf, len, "sh:") || buffer_contains_ci(buf, len, "bash:") || buffer_contains_ci(buf, len, "dash:") || buffer_contains_ci(buf, len, "ash:");
  if (buffer_contains_ci(buf, len, "command not found")){
    return true;
  }
  if (buffer_contains_ci(buf, len, "syntax error") && (has_prefix || buffer_contains_ci(buf, len, "$(") || buffer_contains_ci(buf, len, "&&") || buffer_contains_ci(buf, len, "||") || buffer_contains_ci(buf, len, ";"))){
    return true;
  }
  if (buffer_contains_ci(buf, len, "unexpected token") && (has_prefix || buffer_contains_ci(buf, len, "$(") || buffer_contains_ci(buf, len, "&&") || buffer_contains_ci(buf, len, "||") || buffer_contains_ci(buf, len, ";"))){
    return true;
  }
  if (buffer_contains_ci(buf, len, "not found") && has_prefix){
    return true;
  }
  return false;
}
