/* Capstone Disassembler Engine */
/* M680X Backend by Wolfgang Schwotzer <wolfgang.schwotzer@gmx.net> 2017 */

#include <stdio.h>
#include <string.h>

#include <capstone/platform.h>
#include <capstone/capstone.h>
#include <capstone/m680x.h>
#include "common.h"

#define HD6309_CODE \
  "\x00\x10\x01\x7f\x10\x02\x7f\x10\x03\x10\x04\x10\x05\x7f\x10\x06\x10" \
  "\x07\x10\x08\x10\x09\x10\x0a\x10\x0b\x7f\x10\x0c\x10\x0d\x10\x0e\x10" \
  "\x0f\x10" \
  "\x12\x13\x14\x16\xFF\xFD\x17\x00\x00\x19\x1a\x10\x1C\x10\x1D" \
  "\x1E\x01\x1F\x89" \
  "\x20\xFE\x21\x00\x22\x00\x23\x00\x24\x00\x25\x00\x26\x00" \
  "\x27\x00\x28\x00\x29\x00\x2a\x00\x2b\x00\x2c\x00\x2d\x00" \
  "\x2e\x00\x2f\x00" \
  "\x30\x00\x31\x00\x32\x00\x33\x00" \
  "\x34\x55\x35\xff\x36\x01\x37\xF0" \
  "\x39\x3A\x3B\x3C\x10\x3D\x3F" \
  "\x40\x43\x44\x46\x47\x48\x49\x4A\x4c\x4d\x4F" \
  "\x50\x53\x54\x56\x57\x58\x59\x5A\x5c\x5d\x5F" \
  "\x60\x00\x61\x7f\x00\x62\x7f\x00\x63\x00\x64\x00\x65\x7f\x00\x66\x00" \
  "\x67\x00\x68\x00\x69\x00\x6A\x00\x6b\x7f\x00\x6c\x00\x6d\x00\x6e\x00" \
  "\x6F\x00" \
  "\x70\x10\x00\x71\x7f\x10\x00\x72\x7f\x10\x00\x73\x10\x00\x74\x10\x00" \
  "\x75\x7f\x10\x00\x76\x10\x00\x77\x10\x00\x78\x10\x00\x79\x10\x00" \
  "\x7A\x10\x00\x7b\x7f\x10\x00\x7c\x10\x00\x7d\x10\x00\x7e\x10\x00" \
  "\x7F\x10\x00" \
  "\x80\x10\x81\x10\x82\x10\x83\x10\x00\x84\x10\x85\x10\x86\x10" \
  "\x88\x10\x89\x10\x8a\x10\x8b\x10\x8C\x10\x00\x8D\x00\x8e\x10\x00" \
  "\x90\x10\x91\x10\x92\x10\x93\x10\x94\x10\x95\x10\x96\x10\x97\x10" \
  "\x98\x10\x99\x10\x9a\x10\x9b\x10\x9C\x10\x9D\x10\x9e\x10\x9f\x10" \
  "\xa0\x00\xa1\x00\xa2\x00\xa3\x00\xa4\x00\xa5\x00\xa6\x00\xa7\x00" \
  "\xa8\x00\xa9\x00\xaa\x00\xab\x00\xaC\x00\xaD\x00\xae\x00\xaf\x00" \
  "\xb0\x10\x00\xb1\x10\x00\xb2\x10\x00\xb3\x10\x00\xb4\x10\x00\xb5\x10\x00" \
  "\xb6\x10\x00\xb7\x10\x00\xb8\x10\x00\xb9\x10\x00\xba\x10\x00" \
  "\xbb\x10\x00\xbC\x10\x00\xbD\x10\x00\xbe\x10\x00\xbf\x10\x00" \
  "\xc0\x10\xc1\x10\xc2\x10\xc3\x10\x00\xc4\x10\xc5\x10\xc6\x10" \
  "\xc8\x10\xc9\x10\xca\x10\xcb\x10\xcc\x10\x00\xcd\x49\x96\x02\xd2" \
  "\xcd\x80\x00\x00\x00\xce\x10\x00" \
  "\xd0\x10\xd1\x10\xd2\x10\xd3\x10\xd4\x10\xd5\x10\xd6\x10\xd7\x10" \
  "\xd8\x10\xd9\x10\xda\x10\xdb\x10\xdC\x10\xdD\x10\xde\x10\xdf\x10" \
  "\xe0\x00\xe1\x00\xe2\x00\xe3\x00\xe4\x00\xe5\x00\xe6\x00\xe7\x00" \
  "\xe8\x00\xe9\x00\xea\x00\xeb\x00\xeC\x00\xeD\x00\xee\x00\xef\x00" \
  "\xf0\x10\x00\xf1\x10\x00\xf2\x10\x00\xf3\x10\x00\xf4\x10\x00\xf5\x10\x00" \
  "\xf6\x10\x00\xf7\x10\x00\xf8\x10\x00\xf9\x10\x00\xfa\x10\x00" \
  "\xfb\x10\x00\xfC\x10\x00\xfD\x10\x00\xfe\x10\x00\xff\x10\x00" \
  \
  "\x10\x21\x00\x00\x10\x22\x00\x00\x10\x23\x00\x00" \
  "\x10\x24\x00\x00\x10\x25\x00\x00\x10\x26\x00\x00" \
  "\x10\x27\x00\x00\x10\x28\x00\x00\x10\x29\x00\x00" \
  "\x10\x2a\x00\x00\x10\x2b\x00\x00\x10\x2c\x00\x00" \
  "\x10\x2d\x00\x00\x10\x2e\x00\x00\x10\x2f\x00\x00" \
  "\x10\x30\x01\x10\x31\x12\x10\x32\x23\x10\x33\x34\x10\x34\x46\x10\x35\x67" \
  "\x10\x36\x78\x10\x37\x89\x10\x38\x10\x39\x10\x3a\x10\x3b\x10\x3F" \
  "\x10\x40\x10\x43\x10\x44\x10\x46\x10\x47\x10\x48\x10\x49\x10\x4a\x10\x4c" \
  "\x10\x4d\x10\x4f" \
  "\x10\x53\x10\x54\x10\x56\x10\x59\x10\x5a\x10\x5c\x10\x5d\x10\x5f" \
\
  "\x10\x80\x10\x00\x10\x90\x7f\x10\xa0\x00\x10\xb0\x10\x00" \
  "\x10\x81\x10\x00\x10\x91\x7f\x10\xa1\x00\x10\xb1\x10\x00" \
  "\x10\x82\x10\x00\x10\x92\x7f\x10\xa2\x00\x10\xb2\x10\x00" \
  "\x10\x83\x10\x00\x10\x93\x7f\x10\xa3\x00\x10\xb3\x10\x00" \
  "\x10\x84\x10\x00\x10\x94\x7f\x10\xa4\x00\x10\xb4\x10\x00" \
  "\x10\x85\x10\x00\x10\x95\x7f\x10\xa5\x00\x10\xb5\x10\x00" \
  "\x10\x86\x10\x00\x10\x96\x7f\x10\xa6\x00\x10\xb6\x10\x00" \
  "\x10\x97\x7f\x10\xa7\x00\x10\xb7\x10\x00" \
  "\x10\x88\x10\x00\x10\x98\x7f\x10\xa8\x00\x10\xb8\x10\x00" \
  "\x10\x89\x10\x00\x10\x99\x7f\x10\xa9\x00\x10\xb9\x10\x00" \
  "\x10\x8a\x10\x00\x10\x9a\x7f\x10\xaa\x00\x10\xba\x10\x00" \
  "\x10\x8b\x10\x00\x10\x9b\x7f\x10\xab\x00\x10\xbb\x10\x00" \
  "\x10\x8c\x10\x00\x10\x9c\x7f\x10\xac\x00\x10\xbc\x10\x00" \
  "\x10\x8e\x10\x00\x10\x9e\x7f\x10\xae\x00\x10\xbe\x10\x00" \
  "\x10\x9f\x7f\xaf\x00\x10\xbf\x10\x00" \
  "\x10\xdc\x7f\x10\xec\x00\x10\xfc\x10\x00" \
  "\x10\xdd\x7f\x10\xed\x00\x10\xfd\x10\x00" \
  "\x10\xce\x10\x00\x10\xde\x7f\x10\xee\x00\x10\xfe\x10\x00" \
  "\x10\xdf\x7f\x10\xef\x00\x10\xff\x10\x00" \
  \
  "\x11\x30\x07\x7f\x11\x31\x47\x7f\x11\x32\x87\x7f\x11\x33\x07\x7f" \
  "\x11\x34\x16\x7f\x11\x35\x25\x7f\x11\x36\x34\x7f\x11\x37\x33\x7f" \
  "\x11\x38\x01\x11\x39\x12\x11\x3a\x23\x11\x3b\x34" \
  "\x11\x3c\x7f\x11\x3d\x7f\x11\x3F" \
  "\x11\x43\x11\x4a\x11\x4c\x11\x4d\x11\x4f" \
  "\x11\x53\x11\x5a\x11\x5c\x11\x5d\x11\x4f" \
  "\x11\x80\x10\x11\x90\x7f\x11\xa0\x00\x11\xb0\x10\x00" \
  "\x11\x81\x10\x11\x91\x7f\x11\xa1\x00\x11\xb1\x10\x00" \
  "\x11\x83\x10\x00\x11\x93\x7f\x11\xa3\x00\x11\xb3\x10\x00" \
  "\x11\x86\x10\x11\x96\x7f\x11\xa6\x00\x11\xb6\x10\x00" \
  "\x11\x97\x7f\x11\xa7\x00\x11\xb7\x10\x00" \
  "\x11\x8b\x10\x11\x9b\x7f\x11\xab\x00\x11\xbb\x10\x00" \
  "\x11\x8c\x10\x00\x11\x9c\x7f\x11\xac\x00\x11\xbc\x10\x00" \
  "\x11\x8d\x10\x11\x9d\x7f\x11\xad\x00\x11\xbd\x10\x00" \
  "\x11\x8e\x7f\xff\x11\x9e\x7f\x11\xae\x00\x11\xbe\x10\x00" \
  "\x11\x8f\x7f\xff\x11\x9f\x7f\x11\xaf\x00\x11\xbf\x10\x00" \
  "\x11\xc0\x10\x11\xd0\x7f\x11\xe0\x00\x11\xf0\x10\x00" \
  "\x11\xc1\x10\x11\xd1\x7f\x11\xe1\x00\x11\xf1\x10\x00" \
  "\x11\xc6\x10\x11\xd6\x7f\x11\xe6\x00\x11\xf6\x10\x00" \
  "\x11\xd7\x7f\x11\xe7\x00\x11\xf7\x10\x00" \
  "\x11\xcb\x10\x11\xdb\x7f\x11\xeb\x00\x11\xfb\x10\x00" \
  \
  "\xA6\x07\xA6\x27\xA6\x47\xA6\x67\xA6\x0F\xA6\x10" \
  "\xA6\x80\xA6\x81\xA6\x82\xA6\x83\xA6\x84\xA6\x85\xA6\x86" \
  "\xA6\x88\x7F\xA6\x88\x80\xA6\x89\x7F\xFF\xA6\x89\x80\x00" \
  "\xA6\x8B\xA6\x8C\x10\xA6\x8D\x10\x00" \
  \
  "\xA6\x91\xA6\x93\xA6\x94\xA6\x95\xA6\x96" \
  "\xA6\x98\x7F\xA6\x98\x80\xA6\x99\x7F\xFF\xA6\x99\x80\x00" \
  "\xA6\x9B\xA6\x9C\x10\xA6\x9D\x10\x00\xA6\x9F\x10\x00"

#define HD6309_CODE_ILLEGAL \
"\x15\x18\x1b" \
"\x3e" \
"\x41\x42\x45\x4b\x4e" \
"\x51\x52\x55\x5b\x5e" \
"\x87\x8f" \
"\xc7\xcf" \
\
  "\xa6\x87" \
  "\xa6\xa7\x12" \
  "\xa6\xc7" \
  "\xa6\xe7\x12" \
  "\xa6\x8a\x12" \
  "\xa6\xaa\x12" \
  "\xa6\xca\x12" \
  "\xa6\xea\x12" \
  "\xa6\x8e\x12\x12" \
  "\xa6\xae\x12" \
  "\xa6\xce\x12\x12" \
  "\xa6\xee\x12" \
  "\xa6\x8f" \
  "\xa6\xaf\x12" \
  "\xa6\xcf" \
  "\xa6\xef\x12" \
\
  "\xa6\x97\x12" \
  "\xa6\xb7\x12\x12" \
  "\xa6\xd7\x12" \
  "\xa6\xf7\x12\x12" \
  "\xa6\x90\x12" \
  "\xa6\xb0\x12\x12" \
  "\xa6\xd0\x12" \
  "\xa6\xf0\x12\x12" \
  "\xa6\x92\x12" \
  "\xa6\xb2\x12\x12" \
  "\xa6\xd2\x12" \
  "\xa6\xf2\x12\x12" \
  "\xa6\x97\x12" \
  "\xa6\xb7\x12\x12" \
  "\xa6\xd7\x12" \
  "\xa6\xf7\x12\x12" \
  "\xa6\x9a\x12" \
  "\xa6\xba\x12\x12" \
  "\xa6\xda\x12" \
  "\xa6\xfa\x12\x12" \
  "\xa6\x9e\x12" \
  "\xa6\xbe\x12\x12" \
  "\xa6\xde\x12" \
  "\xa6\xfe\x12\x12" \
  "\xa6\xbf\x12\x12" \
  "\xa6\xdf\x12" \
  "\xa6\xff\x12\x12" \

int main()
{
  struct platform platforms[] =
  {
    {
      CS_ARCH_M680X,
      (cs_mode)(CS_MODE_M680X_6309),
      (unsigned char *)HD6309_CODE,
      sizeof(HD6309_CODE) - 1,
      "M680X_HD6309",
      true,
    },
    {
      CS_ARCH_M680X,
      (cs_mode)(CS_MODE_M680X_6309),
      (unsigned char *)HD6309_CODE_ILLEGAL,
      sizeof(HD6309_CODE_ILLEGAL) - 1,
      "M680X_HD6309_ILLEGAL",
      false,
    },
  };

  test(&platforms[0], ARR_SIZE(platforms));

  return 0;
}
