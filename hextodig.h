/*
    HexToDig Library. Written by Benjamin Jack Cullen.

    A small library for converting hex to digits.
*/

#ifndef HEX_TO_DIG_H
#define HEX_TO_DIG_H

#include <stdint.h>
#include "config.h"

/**
 * Hex to digit.
 * 
 * Convert a single hexadecimal character to its decimal equivalent.
 * 
 * @param hex Specify hex a value
 * @return Returns uint8_t
 */
uint8_t h2d(char hex);

/**
 * 2 Hex to 2 digit.
 * 
 * Convert two hexadecimal characters to a single byte.
 * 
 * @param h1 Specify hex value 1
 * @param h2 Specify hex value 2
 * @return Returns uint8_t
 */
uint8_t h2d2(char h1, char h2);

#endif