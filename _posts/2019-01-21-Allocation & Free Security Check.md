---
title: Allocation & Free Security Check
date: 2019-01-21
---

# Allocation & Free Error

## 함수 별

#### unlink

1. Whether chunk size is equal to the previous size set in the next chunk (in memory)

   (chunk 크기가 다음 chunk의 prev size와 동일한 지) 

   **-> corruped size vs. prev_size**

2. Whether P -> fd -> bk = p and P -> bk -> fd == p

   unsafe unlink 할 때 맞춰줘야하는 조건 binlist에 연결된 fd, bk 를 검증하는 것 **P**(unlink되는 녀석) p(**P**끊고 새로 연결할 녀석) 아마.. 이게 맞을거다 

   예를들어 p 가 0x6020b0 이라 해보자 P -> fd = 0x6020b0 - 0x18 로 설정하고 P -> fd = 0x6020b0 - 0x10 으로 설정한다. fd = p + 0x10, bk = p + 0x18 이기 때문에P -> fd -> bk = p , P -> bk -> fd = p 조건이 성립되게 된다. 요러코롬 unlink가 발동! 되면 0x6020b0에 0x6020b0-0x18값이 들어가게됨! (fake fd)

   **-> corrupted double-linked list**


### _int_malloc

1. While removing the fisrt chunk from fastbin(to service a malloc request), check whether the size of the chunk falls in fast chunk size range

   fastbin 에서 첫 chunk를 malloc으로 반환할 때 size가 fast chunk size인지 확인

   **-> malloc(): memory corruption (fast)**

2. While removing the last chunk (victim) from a smallbin (to service a malloc request), check whether victim->bk->fd and victim are equal

   smallbin에서 마지막 chunk를 malloc으로 반환할 때 victim -> bk -> fd 가 vicimt과 동일한지 확인

   **-> malloc(): smallbin double linked list corrupted**

3. While iterating in unsorted bin, check whether size of current chunk is within minimum (2\*SIZE_SZ) and maximum (av->system_mem) range

   unsorted bin에서 반복하면서 현재 chunk의 크기가 최소(os bit에 맞는 alingment) ~ 최대(system_mem 128kb이었나..) 범위인지 확인

   **-> malloc(): memory corruption**

4. While inserting last remainder chunk into unsorted bin (after splitting a large chunk), check whether unsorted_chunks(av) -> fd -> bk == unsorted_chunks(av)

   last remainder chunk를 unsorted bin에 삽입할 때 fd, bk 가 맞는지 확인 

   **-> malloc(): corrupted unsorted chunks**

5. While inserting last remainder chunk into unsorted bin (after splitting a fast or a small chunk), check whether unsorted_chunks(av) -> fd -> bk == unsorted_chunks(av)

   large chunk를 스플릿해서 생긴 last remainder와 마찬가지로 fast or small chunk를 스플릿 한 last remainder 를 unsorted bin에 넣을 때 fd, bk 검증

   **-> malloc(): corrupted unsorted chunks 2**


### _int_free

1. Check whether p is before p + chunksize(p) in the memory (to avoide wrapping)

   해제될 녀석(p)가 p + chunksize(p) 보다 이전 메모리에 위치하는지 확인

   **-> free(): invalid pointer**

2. Check whether the chunk is at least of size MINSIZE or a multiple of MALLOC_ALIGNMENT

   chunk 의 사이즈가 MINSIZE 이상이거나 Alignment 배수에 맞는지 확인 

   **-> free(): invalid size**

3. For a chunk with size in fastbin range, check if next chunk's size is between minimum and maximum size (av -> system_mem)

   fastbin 범위의 크기를 가진 chunk의 경우, 다음 chunk의 크기가 최소 ~ 최대크기 사이에 있는지 확인

   **-> free(): invalid next size (fast)**

4. While inserting fast chunk into fastbin (at HEAD), check whether the chunk already at HEAD is not the same

   fast chunk 를 fastbin에 넣을 때 이미 fastbin top에 있는 chunk인지 확인

   **-> double free or corruption (fasttop)**

5. While inserting fast chunk into fastbin(at HEAD), check whether size of the chunk at HEAD is same as the chunk to be inserted

   fast chunk 를 fastbin에 삽입할 때 chunk size가 fastbin size에 맞는지 확인

   **-> invaild fastbin entry (free)**

6. If the chunk is not within the size range of fastbin and neither it is a mmapped chunks, check whether it is not the same as the top chunk

   chunk가 fastbin 범위 내에 있지 않고 mmap이 아닌 경우, top chunk인지 확인 (top chunk를 free시키냐 검증하는 것)

   **-> double free or corruption (top)**

7. Check whether next chunk (by memory) is within the boundaries of the arena

   다음 chunk가 main arena(chunk를 관리하는 arena 꼭 main이 아닐 수 있음) 안에 있는지 확인

   **-> double free or corruption (out)**

8. Check whether next chunk's (by memory) previous in use bit is marked

   다음 chunk의 prev_in_use flag가 설정되어 있는지 확인

   **-> double free or corruption (!prev)**

9. Check whether size of next chunk is within the minimum and maximum size

   다음 chunk의 크기가 최소 ~ 최대 size 내에 있는지 확인

   **-> free(): invalid next size (normal)**

10. While inserting the coalesced chunk into unsorted bin, check whether unsorted_chunks(av) -> fd -> bk == unsorted_chunks(av)

    병합 된 chunk를 unsorted bin에 삽입할 때 fd, bk 검증

    **-> free(): corrupted unsorted chunks**

아마 glibc 버전에 따라 다를 것이다.(이건 구 버전 2.23~2.25 정도 인듯 함)

##### 참고 자료 : https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks.html

이 블로그에 자료가 굉장히 많고 좋기 때문에 꼭 보고 정리하는걸 추천!