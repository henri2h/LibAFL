#include <stdint.h>

int main() {
  volatile unsigned char a; // = 0x1;
  volatile unsigned char b; // = 0x0;
  volatile unsigned char c; // = 0x0;

  if (a > b) {
    c = 0x1;
    if (a > 20) {
      c = 0x2;
      if (a == 50) {
        c = 0x3;
        if (b == 24) {
          c = 0x4;
        }
      }
    }
  }
  return c;
}