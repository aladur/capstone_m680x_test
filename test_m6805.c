/* Capstone Disassembler Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

#include <stdio.h>
#include <string.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>
#include <capstone/m680x.h>
#include "common.h"


#define M6805_CODE \
  "\x00\x7f\x00\x01\x7f\x00\x0e\x7f\x00\x0f\x7f\x0d" \
  "\x10\x7f\x11\x7f\x1e\x7f\x1f\x7f" \
  "\x20\xFE\x21\x00\x22\x00\x23\x00\x24\x00\x25\x00\x26\x00\x27\x00" \
  "\x28\x00\x29\x00\x2a\x00\x2b\x00\x2c\x00\x2d\x00\x2e\x00\x2f\x00" \
  "\x30\x7f\x33\x7f\x34\x7f\x36\x7f\x37\x7f" \
  "\x38\x7f\x39\x7f\x3a\x7f\x3c\x7f\x3d\x7f\x3f\x7f" \
  "\x40\x42\x43\x44\x46\x47\x48\x49\x4a\x4c\x4d\x4f" \
  "\x50\x53\x54\x56\x57\x58\x59\x5a\x5c\x5d\x5f" \
  "\x60\x80\x63\x7f\x64\x7f\x66\x7f\x67\x7f\x68\x7f" \
  "\x69\x7f\x6a\x7f\x6c\x7f\x6d\x7f\x6f\x7f" \
  "\x70\x73\x74\x76\x77\x78\x79\x7a\x7c\x7d\x7f" \
  "\x80\x81\x83\x8e\x8f" \
  "\x97\x98\x99\x9a\x9b\x9c\x9d\x9f" \
  "\xa0\x10\xa1\x10\xa2\x10\xa3\x10\xa4\x10\xa5\x10\xa6\x10" \
  "\xa8\x10\xa9\x10\xaa\x10\xab\x10\xad\x10\xae\x10" \
  "\xb0\x10\xb1\x10\xb2\x10\xb4\x10\xb5\x10\xb6\x10" \
  "\xb7\x10\xb8\x10\xb9\x10\xba\x10\xbb\x10\xbc\x10" \
  "\xc0\x10\x00\xc1\x10\x00\xc2\x10\x00\xc3\x10\x00\xc4\x10\x00\xc5\x10\x00" \
  "\xc6\x10\x00\xc7\x10\x00\xc8\x10\x00\xc9\x10\x00\xca\x10\x00\xcb\x10\x00" \
  "\xcc\x10\x00\xcd\x10\x00\xce\x10\x00\xcf\x10\x00" \
  "\xd0\x10\x00\xd1\x10\x00\xd2\x10\x00\xd3\x10\x00\xd4\x10\x00\xd5\x10\x00" \
  "\xd6\x10\x00\xd7\x10\x00\xd8\x10\x00\xd9\x10\x00\xda\x10\x00\xdb\x10\x00" \
  "\xdc\x10\x00\xdd\x10\x00\xde\x10\x00\xdf\x10\x00" \
  "\xe0\x10\xe1\x10\xe2\x10\xe3\x10\xe4\x10\xe5\x10\xe6\x10\xe7\x10" \
  "\xe8\x10\xe9\x10\xea\x10\xeb\x10\xec\x10\xed\x10\xee\x10\xef\x10" \
  "\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"

#define M6805_CODE_ILLEGAL \
  "\x31\x32\x35\x3e" \
  "\x41\x45\x4e" \
  "\x51\x52\x55\x5e" \
  "\x61\x62\x65\x6e" \
  "\x71\x72\x75\x7e" \
  "\x82\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d" \
  "\x90\x91\x92\x93\x94\x95\x96\x9e" \
  "\xa7\xac\xaf"

int main()
{
  struct platform platforms[] =
  {
    {
      CS_ARCH_M680X,
      (cs_mode)(CS_MODE_M680X_6805),
      (unsigned char *)M6805_CODE,
      sizeof(M6805_CODE) - 1,
      "M680X_M6805",
      true,
    },
    {
      CS_ARCH_M680X,
      (cs_mode)(CS_MODE_M680X_6805),
      (unsigned char *)M6805_CODE_ILLEGAL,
      sizeof(M6805_CODE_ILLEGAL) - 1,
      "M680X_M6805_ILLEGAL",
      false,
    },
  };

  test(&platforms[0], ARR_SIZE(platforms));

  return 0;
}
