/*
    HexToDig Library. Written by Benjamin Jack Cullen.

    A small library for converting hex to digits.
*/

#include "hextodig.h"

uint8_t h2d(char hex) {
  // Adjust for A-F or a-f.
  if (hex > 0x39) hex -= 7;
  // Mask to get lower 4 bits.
  return (hex & 0xf);
}

uint8_t h2d2(char h1, char h2) {
  // Shift first digit left by 4 bits and OR with second.
  return (h2d(h1) << 4) | h2d(h2);
}