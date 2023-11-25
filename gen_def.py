#!/usr/bin/env python3
#

import pefile
import sys
import os.path


dll = pefile.PE(sys.argv[1])
system = sys.argv[2]

dll_basename = os.path.splitext(sys.argv[1])[0]

print("EXPORTS")
for export in dll.DIRECTORY_ENTRY_EXPORT.symbols:
    if export.name:
        if (system == "windows"):
            data2 = '{}={}.{},@{}")'.format(export.name.decode(), dll_basename, export.name.decode(), export.ordinal)
            data1 = '#pragma comment(linker,"/export:'
            print(data1 + data2)
        if (system == "linux"):
            print ('{}={}.{}, @{}'.format(export.name.decode(), dll_basename, export.name.decode(), export.ordinal))

