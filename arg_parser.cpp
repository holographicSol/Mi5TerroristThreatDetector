// argparser.c
#include "arg_parser.h"
#include <Arduino.h>
#include <stdlib.h> // strtol
#include <string.h> // strlen, strcpy, strncpy, etc.
#include <stdio.h>  // for error handling if needed
#include <ctype.h>  // for isalnum
#include "strval.h"


void plain_argparser_reset(PlainArgParser* p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
}

void printCommandArgs(PlainArgParser* p) {
    if (!p) return;
    for (int i=0; i < p->i_iter_token; i++) {Serial.print("[arg " + String(i) + "]" + String(p->tokens[i]));}
}

char *tmp_token;

void skipTokens(int index) {for (int i=0; i<index; i++) {tmp_token=strtok(NULL, " ");}}

bool simple_argparser_init_from_buffer(PlainArgParser* p, char* buffer, int index) {
    if (!p || !buffer) return false;
    plain_argparser_reset(p);
    strcpy(p->input_buffer, buffer);
    buffer[strlen(buffer)-1] = '\0'; // corrects last token length
    tmp_token=strtok(buffer, " ");
    skipTokens(index);
    p->i_iter_token=0;
    while (tmp_token!=NULL) {
        strcpy(p->tokens[p->i_iter_token], tmp_token);
        tmp_token=strtok(NULL, " ");
        p->i_iter_token++;
  }
  return true;
  // uncomment to debug
  // printCommandArgs();
}


static bool is_long_flag(const char* arg) {
    return strlen(arg) > 2 && strncmp(arg, "--", 2) == 0;
}

static bool is_short_flag(const char* arg) {
    return strlen(arg) > 1 && arg[0] == '-' && arg[1] != '-';
}

static void clear_buffer(char* buf, size_t max_len) {
    if (max_len > 0) {
        buf[0] = '\0';
    }
}

static bool parse_args(ArgParser* p, int token_count, char** tokens) {
    p->flag_count = 0;
    p->pos_count = 0;

    for (int i = 0; i < token_count; ++i) {
        const char* arg = tokens[i];
        if (!arg || !*arg) continue;

        if (is_long_flag(arg)) {
            if (p->flag_count >= MAX_FLAGS) continue;

            // --flag or --flag=value
            const char* eq = strchr(arg + 2, '=');
            size_t key_len = eq ? (size_t)(eq - (arg + 2)) : strlen(arg + 2);
            if (key_len >= MAX_FLAG_LEN) continue;

            strncpy(p->flags[p->flag_count], arg + 2, key_len);
            p->flags[p->flag_count][key_len] = '\0';

            clear_buffer(p->values[p->flag_count], MAX_VALUE_LEN);
            const char* value_start = NULL;
            size_t val_len = 0;
            if (eq) {
                value_start = eq + 1;
                val_len = strlen(value_start);
            } else if (i + 1 < token_count) {
                const char* next = tokens[i + 1];
                if (!is_long_flag(next) && !is_short_flag(next)) {
                    value_start = next;
                    val_len = strlen(next);
                    ++i;  // Consume next
                }
            }
            if (value_start) {
                if (val_len < MAX_VALUE_LEN) {
                    strcpy(p->values[p->flag_count], value_start);
                } else {
                    strncpy(p->values[p->flag_count], value_start, MAX_VALUE_LEN - 1);
                    p->values[p->flag_count][MAX_VALUE_LEN - 1] = '\0';
                }
            }
            ++p->flag_count;
        } else if (is_short_flag(arg)) {
            size_t len = strlen(arg);
            if (len < 2 || len > 4) continue;  // 1-3 chars after '-', total 2-4

            // Check if all chars after '-' are alphanumeric
            bool valid_short = true;
            for (size_t j = 1; j < len; ++j) {
                if (!isalnum((unsigned char)arg[j])) {
                    valid_short = false;
                    break;
                }
            }
            if (!valid_short) continue;

            if (p->flag_count >= MAX_FLAGS) continue;

            // Flag key: chars after '-'
            size_t key_len = len - 1;
            strncpy(p->flags[p->flag_count], arg + 1, key_len);
            p->flags[p->flag_count][key_len] = '\0';

            clear_buffer(p->values[p->flag_count], MAX_VALUE_LEN);

            // No attached values for shorts; only space-separated
            if (i + 1 < token_count) {
                const char* next = tokens[i + 1];
                if (!is_long_flag(next) && !is_short_flag(next)) {
                    size_t val_len = strlen(next);
                    if (val_len < MAX_VALUE_LEN) {
                        strcpy(p->values[p->flag_count], next);
                    } else {
                        strncpy(p->values[p->flag_count], next, MAX_VALUE_LEN - 1);
                        p->values[p->flag_count][MAX_VALUE_LEN - 1] = '\0';
                    }
                    ++i;
                }
            }
            ++p->flag_count;
        } else {
            // Positional
            if (p->pos_count >= MAX_POSITIONALS) continue;

            size_t arg_len = strlen(arg);
            if (arg_len < MAX_POS_LEN) {
                strcpy(p->positionals[p->pos_count], arg);
            } else {
                strncpy(p->positionals[p->pos_count], arg, MAX_POS_LEN - 1);
                p->positionals[p->pos_count][MAX_POS_LEN - 1] = '\0';
            }
            p->pos_ptrs[p->pos_count] = p->positionals[p->pos_count];
            ++p->pos_count;
        }
    }

    return true;
}

bool argparser_init(ArgParser* p, int argc, char** argv) {
    if (!p || argc < 1) return false;

    memset(p, 0, sizeof(*p));

    // Simulate tokens from argv[1..]
    int token_count = argc - 1;
    char** tokens = argv + 1;
    if (token_count < 0) token_count = 0;

    return parse_args(p, token_count, tokens);
}

bool argparser_init_from_buffer(ArgParser* p, const char* buffer) {
    if (!p || !buffer) return false;

    memset(p, 0, sizeof(*p));

    size_t buf_len = strlen(buffer);
    if (buf_len >= MAX_INPUT_LEN) return false;  // Too long

    strcpy(p->input_buffer, buffer);

    // Manual tokenization: split on whitespace, null-terminate in place
    size_t idx = 0;
    int token_count = 0;
    while (idx < buf_len && token_count < MAX_TOKENS) {
        // Skip whitespace
        while (idx < buf_len && (p->input_buffer[idx] == ' ' || p->input_buffer[idx] == '\t' ||
                                 p->input_buffer[idx] == '\n' || p->input_buffer[idx] == '\r')) {
            ++idx;
        }
        if (idx >= buf_len) break;

        // Start of token
        p->tokens[token_count] = &p->input_buffer[idx];
        ++token_count;

        // Find end of token
        while (idx < buf_len && p->input_buffer[idx] != ' ' && p->input_buffer[idx] != '\t' &&
               p->input_buffer[idx] != '\n' && p->input_buffer[idx] != '\r') {
            ++idx;
        }

        // Null-terminate
        if (idx < buf_len) {
            p->input_buffer[idx] = '\0';
            ++idx;
        }
    }

    return parse_args(p, token_count, p->tokens);
}

void argparser_reset(ArgParser* p) {
    if (!p) return;
    memset(p, 0, sizeof(*p));
}

bool argparser_has_flag(const ArgParser* p, const char* flag) {
    if (!p || !flag) return false;
    for (size_t i = 0; i < p->flag_count; ++i) {
        if (strcmp(p->flags[i], flag) == 0) {
            return true;
        }
    }
    return false;
}

const char* argparser_get_string(const ArgParser* p, const char* flag, const char* default_val) {
    if (!p || !flag) return default_val;
    for (size_t i = 0; i < p->flag_count; ++i) {
        if (strcmp(p->flags[i], flag) == 0) {
            return p->values[i][0] ? p->values[i] : "";
        }
    }
    return default_val;
}

int argparser_get_int(const ArgParser* p, const char* flag, int default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    if(!str_is_int8(val_str)) {return default_val;}
    char* endptr;
    int result = atoi(val_str);
    if (*endptr != '\0') {return default_val;}
    return (int)result;
}

int8_t argparser_get_int8(const ArgParser* p, const char* flag, int8_t default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    if(!str_is_int8(val_str)) {return default_val;}
    char* endptr;
    int8_t result = strtol(val_str, &endptr, 10);
    if (*endptr != '\0') {return default_val;}
    return (int)result;
}

int16_t argparser_get_int16(const ArgParser* p, const char* flag, int16_t default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    if(!str_is_int16(val_str)) {return default_val;}
    char* endptr;
    int16_t result = strtol(val_str, &endptr, 10);
    if (*endptr != '\0') {return default_val;}
    return (int)result;
}

int32_t argparser_get_int32(const ArgParser* p, const char* flag, int32_t default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    if(!str_is_int32(val_str)) {return default_val;}
    char* endptr;
    int32_t result = strtol(val_str, &endptr, 10);
    if (*endptr != '\0') {return default_val;}
    return (int)result;
}

int64_t argparser_get_int64(const ArgParser* p, const char* flag, int64_t default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    if(!str_is_int64(val_str)) {return default_val;}
    char* endptr;
    int64_t result = strtoll(val_str, &endptr, 10);
    if (*endptr != '\0') {return default_val;}
    return (int)result;
}

uint8_t argparser_get_uint8(const ArgParser* p, const char* flag, uint8_t default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    if(!str_is_uint8(val_str)) {return default_val;}
    char* endptr;
    uint8_t result = strtol(val_str, &endptr, 10);
    if (*endptr != '\0') {return default_val;}
    return (int)result;
}

uint16_t argparser_get_uint16(const ArgParser* p, const char* flag, uint16_t default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    if(!str_is_uint16(val_str)) {return default_val;}
    char* endptr;
    uint16_t result = strtol(val_str, &endptr, 10);
    if (*endptr != '\0') {return default_val;}
    return (int)result;
}

uint32_t argparser_get_uint32(const ArgParser* p, const char* flag, uint32_t default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    if(!str_is_uint32(val_str)) {return default_val;}
    char* endptr;
    uint32_t result = strtol(val_str, &endptr, 10);
    if (*endptr != '\0') {return default_val;}
    return (int)result;
}

uint64_t argparser_get_uint64(const ArgParser* p, const char* flag, uint64_t default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    if(!str_is_uint64(val_str)) {return default_val;}
    char* endptr;
    uint64_t result = strtoll(val_str, &endptr, 10);
    if (*endptr != '\0') {return default_val;}
    return (int)result;
}

float argparser_get_float(const ArgParser* p, const char* flag, float default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    char* endptr;
    float result = strtof(val_str, &endptr);
    if (*endptr != '\0') {return default_val;}
    return result;
}

double argparser_get_double(const ArgParser* p, const char* flag, double default_val) {
    const char* val_str = argparser_get_string(p, flag, NULL);
    if (!val_str || !*val_str) return default_val;
    char* endptr;
    double result = strtod(val_str, &endptr);
    if (*endptr != '\0') {return default_val;}
    return result;
}

bool argparser_get_bool(const ArgParser* p, const char* flag) {
    return argparser_has_flag(p, flag);
}

const char* argparser_get_path(const ArgParser* p, const char* default_val) {
    if (!p) return default_val;

    // Prefer value from short "p" flag
    const char* path_val = argparser_get_string(p, "p", NULL);
    if (path_val && *path_val) return path_val;

    // Or value from long "path" flag
    path_val = argparser_get_string(p, "path", NULL);
    if (path_val && *path_val) return path_val;

    // If either flag present (without value), use pos[1] as path (pos[0] is command)
    if (argparser_has_flag(p, "p") || argparser_has_flag(p, "path")) {
        size_t count;
        const char** pos = argparser_get_positionals(p, &count);
        if (count > 1) return pos[1];
    }
    // Fallback: if no flag, use pos[1] as path
    size_t count;
    const char** pos = argparser_get_positionals(p, &count);
    if (count > 1) return pos[1];

    return default_val;
}

const char** argparser_get_positionals(const ArgParser* p, size_t* count) {
    if (count) *count = p ? p->pos_count : 0;
    if (!p) return NULL;
    return (const char**)p->pos_ptrs;
}

size_t argparser_positional_count(const ArgParser* p) {
    return p ? p->pos_count : 0;
}