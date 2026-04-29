#ifndef STRVAL_H
#define STRVAL_H

/*
  strval - Written By Benjamin Jack Cullen
*/

#include <stdbool.h>  // For bool
#include <string.h>   // For strlen, strcmp
#include <ctype.h>    // For isdigit, isalnum
#include <stdlib.h>   // For strtod, strtol
#include <errno.h>    // For errno
#include <limits.h>
#include <math.h>
// #include "config.h"

/**
 * Is String alphanumeric.
 * @param str 
 * @return Return true if str is alphanumeric
 */
bool is_alnum(const char *str);

/**
 * Is String boolean.
 * @param str 
 * @return Return true if str is boolean
 */
bool str_is_bool(const char *str);

/**
 * Is String float.
 * @param str 
 * @return Return true if str is float
 */
bool str_is_float(const char *str);

/**
 * Is String double.
 * @param str 
 * @return Return true if str is double
 */
bool str_is_double(const char *str);

/**
 * Is String long.
 * @param str 
 * @return Return true if str is long
 */
bool str_is_long(const char *str);

/**
 * Is String uint64.
 * @param str 
 * @return Return true if str is uint64
 */
bool str_is_uint64(const char *str);

/**
 * Is String uint32.
 * @param str 
 * @return Return true if str is uint32
 */
bool str_is_uint32(const char *str);

/**
 * Is String uint16.
 * @param str 
 * @return Return true if str is uint16
 */
bool str_is_uint16(const char *str);

/**
 * Is String uint8.
 * @param str 
 * @return Return true if str is uint8
 */
bool str_is_uint8(const char *str);

/**
 * Is String int64.
 * @param str 
 * @return Return true if str is int64
 */
bool str_is_int64(const char *str);

/**
 * Is String int32.
 * @param str 
 * @return Return true if str is int32
 */
bool str_is_int32(const char *str);

/**
 * Is String int16.
 * @param str 
 * @return Return true if str is int16
 */
bool str_is_int16(const char *str);

/**
 * Is String int8.
 * @param str 
 * @return Return true if str is int8
 */
bool str_is_int8(const char *str);

#endif