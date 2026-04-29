
/*
  strval - Written By Benjamin Jack Cullen
*/

#include "strval.h"

bool is_alnum(const char *str) {
    if (str == NULL || *str == '\0') return false;
    for (size_t i = 0; str[i] != '\0'; i++) {
        if (!isalnum((unsigned char)str[i])) return false;
    }
    return true;
}

bool str_is_bool(const char * str) {
  if (strlen(str)!=1) {return false;}
  if ((strcmp(str, "0")==0) || (strcmp(str, "1")==0)) {return true;}
  return false;
}

bool str_is_float(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Check if string is now empty
    if (*str == '\0') {
        return false;
    }
    // Validate string format (basic check for digits, signs, decimal point, exponent)
    bool has_digits = false;
    bool has_decimal = false;
    bool has_exponent = false;
    const char *p = str;

    // Handle optional sign
    if (*p == '+' || *p == '-') {
        p++;
    }
    // Check remaining characters
    while (*p != '\0') {
        if (isdigit((unsigned char)*p)) {
            has_digits = true;
        } else if (*p == '.' && !has_decimal && !has_exponent) {
            has_decimal = true;
        } else if ((*p == 'e' || *p == 'E') && has_digits && !has_exponent) {
            has_exponent = true;
            p++;
            if (*p == '+' || *p == '-') {
                p++;
            }
            if (!isdigit((unsigned char)*p)) { // Exponent must have digits
                return false;
            }
            has_digits = false; // Reset for exponent digits
        } else {
            return false; // Invalid character
        }
        p++;
    }
    // Ensure at least one digit was found
    if (!has_digits) {
        return false;
    }
    // Convert using strtof
    errno = 0; // Reset errno
    char *endptr;
    float temp = strtof(str, &endptr);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0') {
        return false; // Invalid format or trailing characters
    }
    // Check for overflow or underflow
    if (errno == ERANGE) {
        if (temp == HUGE_VALF || temp == -HUGE_VALF) {
            return false; // Overflow
        }
        if (temp == 0.0f) {
            return false; // Underflow
        }
    }
    // Reject inf and nan
    if (isinf(temp) || isnan(temp)) {
        return false;
    }
    return true;
}

bool str_is_double(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Check if string is now empty
    if (*str == '\0') {
        return false;
    }
    // Validate string format (basic check for digits, signs, decimal point, exponent)
    bool has_digits = false;
    bool has_decimal = false;
    bool has_exponent = false;
    const char *p = str;

    // Handle optional sign
    if (*p == '+' || *p == '-') {
        p++;
    }
    // Check remaining characters
    while (*p != '\0') {
        if (isdigit((unsigned char)*p)) {
            has_digits = true;
        } else if (*p == '.' && !has_decimal && !has_exponent) {
            has_decimal = true;
        } else if ((*p == 'e' || *p == 'E') && has_digits && !has_exponent) {
            has_exponent = true;
            p++;
            if (*p == '+' || *p == '-') {
                p++;
            }
            if (!isdigit((unsigned char)*p)) { // Exponent must have digits
                return false;
            }
            has_digits = false; // Reset for exponent digits
        } else {
            return false; // Invalid character
        }
        p++;
    }
    // Ensure at least one digit was found
    if (!has_digits) {
        return false;
    }
    // Convert using strtod
    errno = 0; // Reset errno
    char *endptr;
    double temp = strtod(str, &endptr);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0') {
        return false; // Invalid format or trailing characters
    }
    // Check for overflow or underflow
    if (errno == ERANGE) {
        if (temp == HUGE_VAL || temp == -HUGE_VAL) {
            return false; // Overflow
        }
        if (temp == 0.0) {
            return false; // Underflow
        }
    }
    // Reject inf and nan
    if (isinf(temp) || isnan(temp)) {
        return false;
    }
    return true;
}

bool str_is_long(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Handle optional '+' or '-' sign
    bool is_negative = false;
    if (*str == '+') {
        str++;
    } else if (*str == '-') {
        is_negative = true;
        str++;
    }
    // Check if string is now empty
    if (*str == '\0') {
        return false;
    }
    // Validate that all remaining characters are digits
    for (const char *p = str; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    // Check length and value to prevent overflow
    size_t len = strlen(str);
    const char *max_long_str = is_negative ? "9223372036854775808" : "9223372036854775807"; // LONG_MAX or -LONG_MIN for 64-bit
    size_t max_len = strlen(max_long_str);

    // Adjust max_len for negative numbers (excludes '-')
    if (is_negative) {
        max_len--; // Compare digit part only
    }
    // If string is longer than max_long_str, it’s too large
    if (len > max_len) {
        return false;
    }
    // If equal length, compare lexicographically to check overflow
    if (len == max_len && strcmp(str, max_long_str + (is_negative ? 1 : 0)) > 0) {
        return false;
    }
    // Convert using strtol
    errno = 0; // Reset errno
    char *endptr;
    long temp = strtol(str - (is_negative ? 1 : 0) - (*str == '+' ? 1 : 0), &endptr, 10);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0' || errno == ERANGE) {
        return false;
    }
    // Ensure result fits in long (redundant with string check but included for robustness)
    if (temp > LONG_MAX || temp < LONG_MIN) {
        return false;
    }
    return true;
}

bool str_is_uint64(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace (if any)
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Handle optional '+' sign
    if (*str == '+') {
        str++;
    }
    // Check if string is now empty or contains non-digits
    if (*str == '\0') {
        return false;
    }
    // Validate that all characters are digits
    for (const char *p = str; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    // Check for leading zeros (optional, but we allow them)
    // Compare length and value to ensure it fits in uint64_t
    size_t len = strlen(str);
    const char *max_uint64_str = "18446744073709551615"; // UINT64_MAX
    size_t max_len = strlen(max_uint64_str);

    // If string is longer than max_uint64_str, it may be too large
    if (len > max_len) {
        return false;
    }
    // If equal length, compare lexicographically to check overflow
    if (len == max_len && strcmp(str, max_uint64_str) > 0) {
        return false;
    }
    // Convert using strtoull for parsing
    errno = 0; // Reset errno
    char *endptr;
    unsigned long long temp = strtoull(str, &endptr, 10);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0' || errno == ERANGE) {
        return false;
    }
    return true;
}

bool str_is_int64(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Handle optional '+' or '-' sign
    bool is_negative = false;
    if (*str == '+') {
        str++;
    } else if (*str == '-') {
        is_negative = true;
        str++;
    }
    // Check if string is now empty
    if (*str == '\0') {
        return false;
    }
    // Validate that all remaining characters are digits
    for (const char *p = str; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    // Check length and value to prevent overflow
    size_t len = strlen(str);
    const char *max_int64_str = is_negative ? "9223372036854775808" : "9223372036854775807"; // INT64_MAX or -INT64_MIN
    size_t max_len = strlen(max_int64_str);

    // Adjust max_len for negative numbers (excludes '-')
    if (is_negative) {
        max_len--; // Compare digit part only
    }
    // If string is longer than max_int64_str, it’s too large
    if (len > max_len) {
        return false;
    }
    // If equal length, compare lexicographically to check overflow
    if (len == max_len && strcmp(str, max_int64_str + (is_negative ? 1 : 0)) > 0) {
        return false;
    }
    // Convert using strtoll
    errno = 0; // Reset errno
    char *endptr;
    long long temp = strtoll(str - (is_negative ? 1 : 0) - (*str == '+' ? 1 : 0), &endptr, 10);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0' || errno == ERANGE) {
        return false;
    }
    // Ensure result fits in int64_t
    if (temp > INT64_MAX || temp < INT64_MIN) {
        return false;
    }
    return true;
}

bool str_is_uint32(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Handle optional '+' sign, reject '-' since uint32_t is unsigned
    if (*str == '+') {
        str++;
    } else if (*str == '-') {
        return false; // Negative numbers are invalid for uint32_t
    }
    // Check if string is now empty
    if (*str == '\0') {
        return false;
    }
    // Validate that all remaining characters are digits
    for (const char *p = str; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    // Check length and value to prevent overflow
    size_t len = strlen(str);
    const char *max_uint32_str = "4294967295"; // UINT32_MAX
    size_t max_len = strlen(max_uint32_str);

    // If string is longer than max_uint32_str, it’s too large
    if (len > max_len) {
        return false;
    }
    // If equal length, compare lexicographically to check overflow
    if (len == max_len && strcmp(str, max_uint32_str) > 0) {
        return false;
    }
    // Convert using strtoul
    errno = 0; // Reset errno
    char *endptr;
    unsigned long temp = strtoul(str - (*str == '+' ? 1 : 0), &endptr, 10);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0' || errno == ERANGE) {
        return false;
    }
    // Ensure result fits in uint32_t
    if (temp > UINT32_MAX) {
        return false;
    }
    return true;
}

bool str_is_int32(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Handle optional '+' or '-' sign
    bool is_negative = false;
    if (*str == '+') {
        str++;
    } else if (*str == '-') {
        is_negative = true;
        str++;
    }
    // Check if string is now empty
    if (*str == '\0') {
        return false;
    }
    // Validate that all remaining characters are digits
    for (const char *p = str; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    // Check length and value to prevent overflow
    size_t len = strlen(str);
    const char *max_int32_str = is_negative ? "2147483648" : "2147483647"; // INT32_MAX or -INT32_MIN
    size_t max_len = strlen(max_int32_str);

    // Adjust max_len for negative numbers (excludes '-')
    if (is_negative) {
        max_len--; // Compare digit part only
    }
    // If string is longer than max_int32_str, it’s too large
    if (len > max_len) {
        return false;
    }
    // If equal length, compare lexicographically to check overflow
    if (len == max_len && strcmp(str, max_int32_str + (is_negative ? 1 : 0)) > 0) {
        return false;
    }
    // Convert using strtol
    errno = 0; // Reset errno
    char *endptr;
    long temp = strtol(str - (is_negative ? 1 : 0) - (*str == '+' ? 1 : 0), &endptr, 10);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0' || errno == ERANGE) {
        return false;
    }
    // Ensure result fits in int32_t
    if (temp > INT32_MAX || temp < INT32_MIN) {
        return false;
    }
    return true;
}

bool str_is_uint16(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Handle optional '+' sign, reject '-' since uint16_t is unsigned
    if (*str == '+') {
        str++;
    } else if (*str == '-') {
        return false; // Negative numbers are invalid for uint16_t
    }
    // Check if string is now empty
    if (*str == '\0') {
        return false;
    }
    // Validate that all remaining characters are digits
    for (const char *p = str; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    // Check length and value to prevent overflow
    size_t len = strlen(str);
    const char *max_uint16_str = "65535"; // UINT16_MAX
    size_t max_len = strlen(max_uint16_str);

    // If string is longer than max_uint16_str, it’s too large
    if (len > max_len) {
        return false;
    }
    // If equal length, compare lexicographically to check overflow
    if (len == max_len && strcmp(str, max_uint16_str) > 0) {
        return false;
    }
    // Convert using strtoul
    errno = 0; // Reset errno
    char *endptr;
    unsigned long temp = strtoul(str - (*str == '+' ? 1 : 0), &endptr, 10);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0' || errno == ERANGE) {
        return false;
    }
    // Ensure result fits in uint16_t
    if (temp > UINT16_MAX) {
        return false;
    }
    return true;
}

bool str_is_int16(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Handle optional '+' or '-' sign
    bool is_negative = false;
    if (*str == '+') {
        str++;
    } else if (*str == '-') {
        is_negative = true;
        str++;
    }
    // Check if string is now empty
    if (*str == '\0') {
        return false;
    }
    // Validate that all remaining characters are digits
    for (const char *p = str; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    // Check length and value to prevent overflow
    size_t len = strlen(str);
    const char *max_int16_str = is_negative ? "32768" : "32767"; // INT16_MAX or -INT16_MIN
    size_t max_len = strlen(max_int16_str);

    // Adjust max_len for negative numbers (excludes '-')
    if (is_negative) {
        max_len--; // Compare digit part only
    }
    // If string is longer than max_int16_str, it’s too large
    if (len > max_len) {
        return false;
    }
    // If equal length, compare lexicographically to check overflow
    if (len == max_len && strcmp(str, max_int16_str + (is_negative ? 1 : 0)) > 0) {
        return false;
    }
    // Convert using strtol
    errno = 0; // Reset errno
    char *endptr;
    long temp = strtol(str - (is_negative ? 1 : 0) - (*str == '+' ? 1 : 0), &endptr, 10);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0' || errno == ERANGE) {
        return false;
    }
    // Ensure result fits in int16_t
    if (temp > INT16_MAX || temp < INT16_MIN) {
        return false;
    }
    return true;
}

bool str_is_uint8(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Handle optional '+' sign, reject '-' since uint8_t is unsigned
    if (*str == '+') {
        str++;
    } else if (*str == '-') {
        return false; // Negative numbers are invalid for uint8_t
    }
    // Check if string is now empty
    if (*str == '\0') {
        return false;
    }
    // Validate that all remaining characters are digits
    for (const char *p = str; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    // Check length and value to prevent overflow
    size_t len = strlen(str);
    const char *max_uint8_str = "255"; // UINT8_MAX
    size_t max_len = strlen(max_uint8_str);

    // If string is longer than max_uint8_str, it’s too large
    if (len > max_len) {
        return false;
    }
    // If equal length, compare lexicographically to check overflow
    if (len == max_len && strcmp(str, max_uint8_str) > 0) {
        return false;
    }
    // Convert using strtoul
    errno = 0; // Reset errno
    char *endptr;
    unsigned long temp = strtoul(str - (*str == '+' ? 1 : 0), &endptr, 10);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0' || errno == ERANGE) {
        return false;
    }
    // Ensure result fits in uint8_t
    if (temp > UINT8_MAX) {
        return false;
    }
    return true;
}

bool str_is_int8(const char *str) {
    // Check for null or empty string
    if (str == NULL || *str == '\0') {
        return false;
    }
    // Skip leading whitespace
    while (isspace((unsigned char)*str)) {
        str++;
    }
    // Handle optional '+' or '-' sign
    bool is_negative = false;
    if (*str == '+') {
        str++;
    } else if (*str == '-') {
        is_negative = true;
        str++;
    }
    // Check if string is now empty
    if (*str == '\0') {
        return false;
    }
    // Validate that all remaining characters are digits
    for (const char *p = str; *p != '\0'; p++) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
    }
    // Check length and value to prevent overflow
    size_t len = strlen(str);
    const char *max_int8_str = is_negative ? "128" : "127"; // INT8_MAX or -INT8_MIN
    size_t max_len = strlen(max_int8_str);

    // Adjust max_len for negative numbers (excludes '-')
    if (is_negative) {
        max_len--; // Compare digit part only
    }
    // If string is longer than max_int8_str, it’s too large
    if (len > max_len) {
        return false;
    }
    // If equal length, compare lexicographically to check overflow
    if (len == max_len && strcmp(str, max_int8_str + (is_negative ? 1 : 0)) > 0) {
        return false;
    }
    // Convert using strtol
    errno = 0; // Reset errno
    char *endptr;
    long temp = strtol(str - (is_negative ? 1 : 0) - (*str == '+' ? 1 : 0), &endptr, 10);

    // Check for conversion errors
    if (endptr == str || *endptr != '\0' || errno == ERANGE) {
        return false;
    }
    // Ensure result fits in int8_t
    if (temp > INT8_MAX || temp < INT8_MIN) {
        return false;
    }
    return true;
}
