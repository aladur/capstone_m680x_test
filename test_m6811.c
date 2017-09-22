/* Capstone Disassembler Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

#include <stdio.h>
#include <string.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>
#include <capstone/m680x.h>
#include "common.h"


#define M6811_CODE \
  "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" \
  "\x10\x11\x12\x7f\x10\x00\x13\x7f\x10\x00\x14\x7f\x10\x15\x7f\x10" \
  "\x16\x17\x19\x1b\x1c\x7f\x10\x1d\x7f\x10\x1e\x7f\x10\x00\x1f\x7f\x10\x00" \
  "\x20\xFE\x21\x00\x22\x00\x23\x00\x24\x00\x25\x00\x26\x00\x27\x00" \
  "\x28\x00\x29\x00\x2a\x00\x2b\x00\x2c\x00\x2d\x00\x2e\x00\x2f\x00" \
  "\x30\x31\x32\x33\x34\x35\x36\x37" \
  "\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f" \
  "\x40\x43\x44\x46\x47\x48\x49\x4a\x4c\x4d\x4f" \
  "\x50\x53\x54\x56\x57\x58\x59\x5a\x5c\x5d\x5f" \
  "\x60\x7f\x63\x7f\x64\x7f\x66\x7f\x67\x7f\x68\x7f" \
  "\x69\x7f\x6a\x7f\x6c\x7f\x6d\x7f\x6e\x7f\x6f\x7f" \
  "\x70\x10\x00\x73\x10\x00\x74\x10\x00\x76\x10\x00\x77\x10\x00\x78\x10\x00" \
  "\x79\x10\x00\x7a\x10\x00\x7c\x10\x00\x7d\x10\x00\x7e\x10\x00\x7f\x10\x00" \
  "\x80\x10\x81\x10\x82\x10\x83\x10\x00\x84\x10\x85\x10\x86\x10\x88\x10" \
  "\x89\x10\x8a\x10\x8b\x10\x8c\x10\x00\x8d\x10\x8e\x10\x00\x8f" \
  "\x90\x10\x91\x10\x92\x10\x93\x10\x94\x10\x95\x10\x96\x10\x97\x10\x98\x10" \
  "\x99\x10\x9a\x10\x9b\x10\x9c\x10\x9d\x10\x9e\x10\x9f\x10" \
  "\xa0\x10\xa1\x10\xa2\x10\xa3\x10\xa4\x10\xa5\x10\xa6\x10\xa7\x10\xa8\x10" \
  "\xa9\x10\xaa\x10\xab\x10\xac\x10\xad\x10\xae\x10\xaf\x10" \
  "\xb0\x10\x00\xb1\x10\x00\xb2\x10\x00\xb3\x10\x00\xb4\x10\x00\xb5\x10\x00" \
  "\xb6\x10\x00\xb7\x10\x00\xb8\x10\x00\xb9\x10\x00\xba\x10\x00\xbb\x10\x00" \
  "\xbc\x10\x00\xbd\x10\x00\xbe\x10\x00\xbf\x10\x00" \
  "\xc0\x10\xc1\x10\xc2\x00\xc3\x10\xc4\x10\xc5\x00\xc6\x10\xc8\x10" \
  "\xc9\x10\xca\x10\xcb\x10\xcc\x10\x00\xce\x10\x00\xcf" \
  "\xd0\x10\xd1\x10\xd2\x00\xd3\x10\xd4\x10\xd5\x00\xd6\x10\xd7\x10\xd8\x10" \
  "\xd9\x10\xda\x10\xdb\x10\xdc\x10\xdd\x10\xde\x10\xdf\x10" \
  "\xe0\x10\xe1\x10\xe2\x10\xe3\x10\xe4\x10\xe5\x10\xe6\x10\xe7\x10\xe8\x10" \
  "\xe9\x10\xea\x10\xeb\x10\xec\x10\xed\x10\xee\x10\xef\x10" \
  "\xf0\x10\x00\xf1\x10\x00\xf2\x10\x00\xf3\x10\x00\xf4\x10\x00\xf5\x10\x00" \
  "\xf6\x10\x00\xf7\x10\x00\xf8\x10\x00\xf9\x10\x00\xfa\x10\x00\xfb\x10\x00" \
  "\xfc\x10\x00\xfd\x10\x00\xfe\x10\x00\xff\x10\x00" \
\
  "\x18\x08\x18\x09\x18\x1c\x7f\x10\x18\x1d\x7f\x10\x18\x1e\x7f\x10\x00" \
  "\x18\x1f\x7f\x10\x00" \
  "\x18\x30\x18\x35\x18\x38\x18\x3a\x18\x3c" \
  "\x18\x60\x7f\x18\x63\x7f\x18\x64\x7f\x18\x66\x7f\x18\x67\x7f\x18\x68\x7f" \
  "\x18\x69\x7f\x18\x6a\x7f\x18\x6c\x7f\x18\x6d\x7f\x18\x6e\x7f\x18\x6f\x7f" \
  "\x18\x8c\x10\x00\x18\x8f" \
  "\x18\x9c\x10" \
  "\x18\xa0\x7f\x18\xa1\x7f\x18\xa2\x7f\x18\xa3\x7f\x18\xa4\x7f\x18\xa5\x7f" \
  "\x18\xa6\x7f\x18\xa7\x7f\x18\xa8\x7f\x18\xa9\x7f\x18\xaa\x7f\x18\xab\x7f" \
  "\x18\xac\x7f\x18\xad\x7f\x18\xae\x7f\x18\xaf\x7f" \
  "\x18\xbc\x10\x00" \
  "\x18\xce\x10\x00" \
  "\x18\xde\x10\x18\xdf\x10" \
  "\x18\xe0\x7f\x18\xe1\x7f\x18\xe2\x7f\x18\xe3\x7f\x18\xe4\x7f\x18\xe5\x7f" \
  "\x18\xe6\x7f\x18\xe7\x7f\x18\xe8\x7f\x18\xe9\x7f\x18\xea\x7f\x18\xeb\x7f" \
  "\x18\xec\x7f\x18\xed\x7f\x18\xee\x7f\x18\xef\x7f" \
  "\x18\xfe\x10\x00\x18\xff\x10\x00" \
\
  "\x1a\x83\x10\x00" \
  "\x1a\x93\x7f" \
  "\x1a\xa3\x7f\x1a\xac\x7f" \
  "\x1a\xb3\x10\x00" \
  "\x1a\xee\x7f\x1a\xef\x7f" \
\
  "\xcd\xa3\x7f\xcd\xac\x7f" \
  "\xcd\xee\x7f\xcd\xef\x7f"

#define M6811_CODE_ILLEGAL \
  "\x18\x1a" \
  "\x41\x42\x45\x4b\x4e" \
  "\x51\x52\x55\x5b\x5e" \
  "\x61\x87\x62\x87\x65\x87\x6b\x87" \
  "\x71\x87\x87\x72\x87\x87\x75\x87\x87\x7b\x87\x87" \
  "\x87\x87" \
  "\xc7\x87"

int main()
{
  struct platform platforms[] =
  {
    {
      CS_ARCH_M680X,
      (cs_mode)(CS_MODE_M680X_6811),
      (unsigned char *)M6811_CODE,
      sizeof(M6811_CODE) - 1,
      "M680X_M68HC01",
      true,
    },
    {
      CS_ARCH_M680X,
      (cs_mode)(CS_MODE_M680X_6811),
      (unsigned char *)M6811_CODE_ILLEGAL,
      sizeof(M6811_CODE_ILLEGAL) - 1,
      "M680X_M68HC11_ILLEGAL",
      false,
    },
  };

  test(&platforms[0], ARR_SIZE(platforms));

  return 0;
}