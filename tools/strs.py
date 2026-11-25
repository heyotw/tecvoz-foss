# Resolve Ghidra "(char *)(DAT_xxxx + 0xyyyy)" PIC string refs in a decompiled dump. Ghidra image base = 0x10000.
import re, struct, sys
so, dump, fn = sys.argv[1], sys.argv[2], sys.argv[3]
b = open(so, "rb").read()
def cstr(a):
    e = b.index(b"\0", a); return b[a:e].decode("latin-1")
text = open(dump).read()
start = text.index("==== " + fn + " @"); end = text.find("// ==== ", start + 10)
for m in re.finditer(r"DAT_([0-9a-f]+) \+ 0x([0-9a-f]+)", text[start:end]):
    lit, pc = int(m.group(1), 16) - 0x10000, int(m.group(2), 16)
    a = (struct.unpack_from("<I", b, lit)[0] + pc - 0x10000) & 0xffffffff
    try: print(" ", repr(cstr(a)))
    except Exception: pass
