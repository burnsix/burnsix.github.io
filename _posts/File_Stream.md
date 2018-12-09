---
title: File Stream Pointer
date: 2018-12-07 02:04
---

# File_Stream Pointer

House_of_orange를 이해하기 위해서.. pwnable.tw의 seethefile 문제를 풀기 위해서... File Stream 구조를 알아야한다.. 일단 내가 제일 많이 쓰고 있는 우분투 16.04버전 기준이다. 다른 버전은 이것과 동일하지 않을 수 있다.

일단 바로 예제코드로 알아보도록 하자..

```c
#include <stdio.h>
#include <stdlib.h>

FILE * fp;
char f[30];

int main() {
	fp = fopen("file","r");
	fread(f,30,1,fp);
	printf("File : %s",f);
	fclose(fp);
}
```

> 항가항가

```assembly
gdb-peda$ par
addr                prev                size                 status              fd                bk
0x602000            0x0                 0x230                Used                None              None
0x602230            0x7ffff7dd0260      0x1010               Used                None              None
0x603240            0x0                 0x410                Used                None              None
```

```assembly
gdb-peda$ x/32gx 0x602000
0x602000:	0x0000000000000000	0x0000000000000231
0x602010:	0x00000000fbad2488	0x000000000060225e
0x602020:	0x000000000060225f	0x0000000000602240
0x602030:	0x0000000000602240	0x0000000000602240
0x602040:	0x0000000000602240	0x0000000000602240
0x602050:	0x0000000000603240	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	[0x00007ffff7dd2540]
0x602080:	0x0000000000000003	0x0000000000000000
0x602090:	0x0000000000000000	0x00000000006020f0
0x6020a0:	0xffffffffffffffff	0x0000000000000000
0x6020b0:	0x0000000000602100	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x00000000ffffffff	0x0000000000000000
0x6020e0:	0x0000000000000000	[0x00007ffff7dd06e0]
```

fp 찍힌 곳에 파일 스트림 구조인데 32비트나 64비트나 크게 차이나는 부분은 없다 똑같이 0x00007ffff7dd2540 요 녀석은 stderr이고 0x00007ffff7dd06e0 마찬가지로 _IO_file_jumps 요 녀석이다.. (하나하나 다 어디에 쓰이는지 알고 싶긴 하지만.. orange할 때 업그레이드를..!)

> 매직값 + 임시버퍼*8 + dummy(0)\*4 + stderr + 3 + dummy(0)\*2 + 무언가 쓸 수 있는 영역의 주소(맞는진 모르겠다 비어있으면 제대로 동작하지 않았음) + 0xffffffffffffffff + dummy(0)\*5 + 0x00000000ffffffff + dummy(0)\*2 + _IO_file_jumps 요런 식으로 구조가 짜여서 있다..

```c
#define _IO_MAGIC 0xFBAD0000 /* Magic number */
#define _OLD_STDIO_MAGIC 0xFABC0000 /* Emulate old stdio. */
#define _IO_MAGIC_MASK 0xFFFF0000
#define _IO_USER_BUF 1 /* User owns buffer; don't delete it on close. */
#define _IO_UNBUFFERED 2
#define _IO_NO_READS 4 /* Reading not allowed */
#define _IO_NO_WRITES 8 /* Writing not allowd */
#define _IO_EOF_SEEN 0x10
#define _IO_ERR_SEEN 0x20
#define _IO_DELETE_DONT_CLOSE 0x40 /* Don't call close(_fileno) on cleanup. */
#define _IO_LINKED 0x80 /* Set if linked (using _chain) to streambuf::_list_all.*/
#define _IO_IN_BACKUP 0x100
#define _IO_LINE_BUF 0x200
#define _IO_TIED_PUT_GET 0x400 /* Set if put and get pointer logicly tied. */
#define _IO_CURRENTLY_PUTTING 0x800
#define _IO_IS_APPENDING 0x1000
#define _IO_IS_FILEBUF 0x2000
#define _IO_BAD_SEEN 0x4000
#define _IO_USER_LOCK 0x8000
```

magic 값이나 flag의 정보는 /usr/include/libio.h 여기에서 확인할 수 있다. magic number + _IO_IS_FILEBUF + _IO_TIED_PUT_GET + _IO_LINKED + _IO_NO_WRITES 요렇게 박혀있다 여기서는..

그리고 File Stream Pointer에서 중요한 구조를 몇가지 살펴보자.

```c
struct _ IO_FILE_plus * _ IO_list_all = & _ IO_2_1_stderr_ ;

/* We always allocate an extra word following an _IO_FILE.
   This contains a pointer to the function jump table used.
   This is for compatibility with C++ streambuf; the word can
   be used to smash to a pointer to a virtual function table. */
 
struct _IO_FILE_plus
{
    _IO_FILE file;
    const struct _IO_jump_t *vtable;
};
struct _IO_jump_t
{
    JUMP_FIELD(size_t, __dummy);
    JUMP_FIELD(size_t, __dummy2);
    JUMP_FIELD(_IO_finish_t, __finish);
    JUMP_FIELD(_IO_overflow_t, __overflow);
    JUMP_FIELD(_IO_underflow_t, __underflow);
    JUMP_FIELD(_IO_underflow_t, __uflow);
    JUMP_FIELD(_IO_pbackfail_t, __pbackfail);
    /* showmany */
    JUMP_FIELD(_IO_xsputn_t, __xsputn);
    JUMP_FIELD(_IO_xsgetn_t, __xsgetn);
    JUMP_FIELD(_IO_seekoff_t, __seekoff);
    JUMP_FIELD(_IO_seekpos_t, __seekpos);
    JUMP_FIELD(_IO_setbuf_t, __setbuf);
    JUMP_FIELD(_IO_sync_t, __sync);
    JUMP_FIELD(_IO_doallocate_t, __doallocate);
    JUMP_FIELD(_IO_read_t, __read);
    JUMP_FIELD(_IO_write_t, __write);
    JUMP_FIELD(_IO_seek_t, __seek);
    JUMP_FIELD(_IO_close_t, __close);
    JUMP_FIELD(_IO_stat_t, __stat);
    JUMP_FIELD(_IO_showmanyc_t, __showmanyc);
    JUMP_FIELD(_IO_imbue_t, __imbue);
 #if 0
    get_column;
    set_column;
 #endif
};
/*Initialize the _IO_file_jumps*/
#define JUMP_INIT(NAME, VALUE) VALUE
const struct _IO_jump_t _IO_file_jumps =
{
   JUMP_INIT_DUMMY,
   JUMP_INIT(finish, _IO_file_finish),
   JUMP_INIT(overflow, _IO_file_overflow),
   JUMP_INIT(underflow, _IO_file_underflow),
   JUMP_INIT(uflow, _IO_default_uflow),
   JUMP_INIT(pbackfail, _IO_default_pbackfail),
   JUMP_INIT(xsputn, _IO_file_xsputn),
   JUMP_INIT(xsgetn, _IO_file_xsgetn),
   JUMP_INIT(seekoff, _IO_new_file_seekoff),
   JUMP_INIT(seekpos, _IO_default_seekpos),
   JUMP_INIT(setbuf, _IO_new_file_setbuf),
   JUMP_INIT(sync, _IO_new_file_sync),
   JUMP_INIT(doallocate, _IO_file_doallocate),
   JUMP_INIT(read, _IO_file_read),
   JUMP_INIT(write, _IO_new_file_write),
   JUMP_INIT(seek, _IO_file_seek),
   JUMP_INIT(close, _IO_file_close),
   JUMP_INIT(stat, _IO_file_stat),
   JUMP_INIT(showmanyc, _IO_default_showmanyc),
   JUMP_INIT(imbue, _IO_default_imbue)
};
#define JUMP_FIELD(TYPE, NAME) TYPE NAME
struct _IO_FILE 
{
    int _flags;       /* High-order word is _IO_MAGIC; rest is flags. */
  #define _IO_file_flags _flags
 
    /* The following pointers correspond to the C++ streambuf protocol. */
    /* Note:  Tk uses the _IO_read_ptr and _IO_read_end fields directly. */
    char* _IO_read_ptr;   /* Current read pointer */
    char* _IO_read_end;   /* End of get area. */
    char* _IO_read_base;  /* Start of putback+get area. */
    char* _IO_write_base; /* Start of put area. */
    char* _IO_write_ptr;  /* Current put pointer. */
    char* _IO_write_end;  /* End of put area. */
    char* _IO_buf_base;   /* Start of reserve area. */
    char* _IO_buf_end;    /* End of reserve area. */
    /* The following fields are used to support backing up and undo. */
    char *_IO_save_base; /* Pointer to start of non-current get area. */
    char *_IO_backup_base;  /* Pointer to first valid character of backup area */
    char *_IO_save_end; /* Pointer to end of non-current get area. */
 
    struct _IO_marker *_markers;
 
    struct _IO_FILE *_chain;
 
    int _fileno;
  #if 0
    int _blksize;
  #else
    int _flags2;
  #endif
    _IO_off_t _old_offset; /* This used to be _offset but it's too small.  */
 
  #define __HAVE_COLUMN /* temporary */
    /* 1+column number of pbase(); 0 is unknown. */
    unsigned short _cur_column;
    signed char _vtable_offset;
    char _shortbuf[1];
 
    /*  char* _save_gptr;  char* _save_egptr; */
 
    _IO_lock_t *_lock;
  #ifdef _IO_USE_OLD_IO_FILE
};
```

윽 극혐 File 관련 함수를 사용하면 _IO_jump_t 라는 vtable이 생성되는 듯 하다.

```assembly
gdb-peda$ x/12gx 0x00007ffff7dd06e0
0x7ffff7dd06e0 <_IO_file_jumps>:	0x0000000000000000	0x0000000000000000
0x7ffff7dd06f0 <_IO_file_jumps+16>:	0x00007ffff7a869c0	0x00007ffff7a87730
0x7ffff7dd0700 <_IO_file_jumps+32>:	0x00007ffff7a874a0	0x00007ffff7a88600
0x7ffff7dd0710 <_IO_file_jumps+48>:	0x00007ffff7a89980	0x00007ffff7a861e0
0x7ffff7dd0720 <_IO_file_jumps+64>:	0x00007ffff7a85ec0	0x00007ffff7a854c0
0x7ffff7dd0730 <_IO_file_jumps+80>:	0x00007ffff7a88a00	0x00007ffff7a85430

gdb-peda$ x/gx 0x00007ffff7a869c0
0x7ffff7a869c0 <_IO_new_file_finish>
```

const struct _IO_jump_t *vtable; 을 살펴보면 더블 포인터 형식으로 실제 File 관련 함수 주소가 박혀있다. 결국 file 관련 함수를 실행하면 저 vtable에서 참조해서 사용한다는 뜻이기 때문에.. 저 녀석을 변조시켜주면 익스가 가능할 것이다.

```c
ypedef struct _IO_FILE FILE;

extern struct _IO_FILE_plus _IO_2_1_stdin_;
extern struct _IO_FILE_plus _IO_2_1_stdout_;
extern struct _IO_FILE_plus _IO_2_1_stderr_;

_IO_FILE *stdin = (FILE *) &_IO_2_1_stdin_;
_IO_FILE *stdout = (FILE *) &_IO_2_1_stdout_;
_IO_FILE *stderr = (FILE *) &_IO_2_1_stderr_;

#  define DEF_STDFILE(NAME, FD, CHAIN, FLAGS) \
  struct _IO_FILE_plus NAME \
    = {FILEBUF_LITERAL(CHAIN, FLAGS, FD, NULL), \
      &_IO_file_jumps};

DEF_STDFILE(_IO_2_1_stdin_, 0, 0, _IO_NO_WRITES);
DEF_STDFILE(_IO_2_1_stdout_, 1, &_IO_2_1_stdin_, _IO_NO_READS);
DEF_STDFILE(_IO_2_1_stderr_, 2, &_IO_2_1_stdout_, _IO_NO_READS+_IO_UNBUFFERED)

#  define FILEBUF_LITERAL(CHAIN, FLAGS, FD, WDP) \
      { _IO_MAGIC+_IO_LINKED+_IO_IS_FILEBUF+FLAGS, \
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (_IO_FILE *) CHAIN, FD, \
  0, _IO_pos_BAD, 0, 0, { 0 }, 0, _IO_pos_BAD, \
  0 }
```

표준 입출력이 구조체라는 것은 이번에 처음 알게되었다..

```assembly
gdb-peda$ p *(FILE*)stdout
$1 = {
  _flags = 0xfbad2a84,
  _IO_read_ptr = 0x603250 "File : HHHHHEEEEELLLLLOOOOOWWWWW!!!!!",
  _IO_read_end = 0x603250 "File : HHHHHEEEEELLLLLOOOOOWWWWW!!!!!",
  _IO_read_base = 0x603250 "File : HHHHHEEEEELLLLLOOOOOWWWWW!!!!!",
  _IO_write_base = 0x603250 "File : HHHHHEEEEELLLLLOOOOOWWWWW!!!!!",
  _IO_write_ptr = 0x603275 "",
  _IO_write_end = 0x603250 "File : HHHHHEEEEELLLLLOOOOOWWWWW!!!!!",
  _IO_buf_base = 0x603250 "File : HHHHHEEEEELLLLLOOOOOWWWWW!!!!!",
  _IO_buf_end = 0x603650 "",
  _IO_save_base = 0x0,
  _IO_backup_base = 0x0,
  _IO_save_end = 0x0,
  _markers = 0x0,
  [_chain = 0x7ffff7dd18e0 <_IO_2_1_stdin_>,]
  _fileno = 0x1,
  _flags2 = 0x0,
  _old_offset = 0xffffffffffffffff,
  _cur_column = 0x0,
  _vtable_offset = 0x0,
  _shortbuf = "",
  _lock = 0x7ffff7dd3780 <_IO_stdfile_1_lock>,
  _offset = 0xffffffffffffffff,
  _codecvt = 0x0,
  _wide_data = 0x7ffff7dd17a0 <_IO_wide_data_1>,
  _freeres_list = 0x0,
  _freeres_buf = 0x0,
  __pad5 = 0x0,
  _mode = 0xffffffff,
  _unused2 = '\000' <repeats 19 times>
}
```

gdb에서 요런식으로 확인 가능한 부분이다

아직 깊게까지는 분석하기 힘들기 때문에.. 차차 하기로 하자..ㅠ

```assembly
gdb-peda$ x/gx 0x00007ffff7a85340
0x7ffff7a85340 <__GI__IO_file_close>:	0x000003b8707f6348
```

일단 fclose를 할 때 익스를 한다 생각하고 gdb에서 값을 바꿔보자

```assembly
0x6020e0:	0x0000000000000000	[0x00007ffff7dd06e0]
0x6020f0:	0x0000000000000000	0x0000000000000000
->
gdb-peda$ x/100gx 0x602000
0x602000:	0x0000000000000000	0x0000000000000231
0x602010:	0x00000000fbad2408	0x000000000060225e
0x602020:	0x000000000060225f	0x0000000000602240
0x602030:	0x0000000000602240	0x0000000000602240
0x602040:	0x0000000000602240	0x0000000000602240
0x602050:	0x0000000000603240	0x0000000000000000
0x602060:	0x0000000000000000	0x0000000000000000
0x602070:	0x0000000000000000	0x00007ffff7dd2540
0x602080:	0x0000000000000003	0x0000000000000000
0x602090:	0x0000000000000000	0x00000000006020f0
0x6020a0:	0xffffffffffffffff	0x0000000000000000
0x6020b0:	0x0000000000602100	0x0000000000000000
0x6020c0:	0x0000000000000000	0x0000000000000000
0x6020d0:	0x00000000ffffffff	0x0000000000000000
0x6020e0:	0x0000000000000000	[0x0000000000602100]
0x6020f0:	0x0000000100000001	0x00007ffff7fe6700
0x602100:	0x4141414141414141	0x4141414141414141
0x602110:	0x4141414141414141	0x4141414141414141
0x602120:	0x4141414141414141	0x4141414141414141
0x602130:	0x4141414141414141	0x4141414141414141
0x602140:	0x4141414141414141	0x4141414141414141
0x602150:	0x4141414141414141	0x4141414141414141
0x602160:	0x4141414141414141	0x4141414141414141
0x602170:	0x4141414141414141	0x4141414141414141
0x602180:	0x4141414141414141	0x4141414141414141
0x602190:	0x4141414141414141	0x4141414141414141
0x6021a0:	0x4141414141414141	0x4141414141414141
0x6021b0:	0x4141414141414141	0x4141414141414141
0x6021c0:	0x4141414141414141	0x4141414141414141
0x6021d0:	0x4141414141414141	0x4141414141414141
0x6021e0:	0x4141414141414141	0x4141414141414141
0x6021f0:	0x4141414141414141	0x4141414141414141
```

간단하게 바꿔보았다. vtable을 바꿔주고 오프셋은 맞추기귀찮아서 a로 쭉 밀었을 때 fclose가 실행이되면

```assembly
   0x7ffff7a86950 <_IO_new_file_close_it+272>:	mov    rax,QWORD PTR [rbx+0xd8]
   0x7ffff7a86957 <_IO_new_file_close_it+279>:	mov    rdi,rbx
=> 0x7ffff7a8695a <_IO_new_file_close_it+282>:	call   QWORD PTR [rax+0x88]

Program received signal SIGSEGV, Segmentation fault.
```

이 부분에서 세그폴이 뜨게된다.

```assembly
gdb-peda$ x/gx $rbx+0xd8
0x6020e8:	0x0000000000602100
이 녀석이 바로 변조한 vtable

gdb-peda$ x/gx $rax+0x88
0x602188:	0x4141414141414141
gdb-peda$ x/gx 0x00007ffff7a85340
0x7ffff7a85340 <__GI__IO_file_close>:	0x000003b8707f6348
vtable + 0x88에 __GI__IO_file_close가 위치해 있다. 
```

이런 식으로 익스가 가능하다. (틀린 부분이 있다면 지적해 주세요!)