from ctypes import *
import os,sys
import struct

PROCESS_ALL_ACCESS = 0x1F0FFF
TOP_LIMIT = 0x80000000

def usage():
   print >>sys.stderr, "usage: %s <pid> <target file>" % sys.argv[0]
   sys.exit(1)

def updateProgressBar(curAddr):
   amount = int(round((float(curAddr)/TOP_LIMIT) * 10))
   sys.stdout.write("\r[%s%s]" % (amount * "#", (10-amount)*" "))


def main():
   if len(sys.argv) < 3:
      usage()

   arg = sys.argv[1]

   if arg.startswith("0x"):
      pid = int(arg, 0x10)
   else:
      pid = int(arg)


   hProcess = windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
   if hProcess == 0:
      print >>sys.stderr, "Unable to open process 0x%X, aborting..." % pid
      sys.exit(1)

   addr = 0
   buf = create_string_buffer(0x1000)
   count = c_ulong(0)
   fout = open(sys.argv[2], "wb")
   while addr<TOP_LIMIT:
      if (addr%0x10000000) == 0:
         updateProgressBar(addr)
      if windll.kernel32.ReadProcessMemory(hProcess, addr, buf, 0x1000, byref(count)):
         fout.write("P" + struct.pack("<L", addr) + struct.pack("<L", -1))
         fout.write(buf.raw)
      addr += 0x1000

   updateProgressBar(addr)
   sys.stdout.write("\n")
   
   fout.close()


if __name__ == "__main__":
   main()