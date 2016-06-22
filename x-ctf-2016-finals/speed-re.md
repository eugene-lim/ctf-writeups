## Speed RE
Points: 15

Category: Reversing

Description:

> Play a speed game!

> nc bg1.spro.ink 4243

----

After connecting, we're told the following:

>Welcome to the Speed Reversing Challenge!

>In this game, you are given 5 seconds to reverse a randomly generated binary.

>Complete 50 rounds and you'll get the flag. Ready? Go!

We're also given a binary encoded in base64.

After decoding it, we find that it is a 64-bit ELF.

>$ file 1.out

> 1.out: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.32, not stripped

Running the binary, we realise that it asks for an input, and outputs whether the input is accepted. Trying inputs with varying length, we found that the binary only reads up to 3 characters.

Next, looking at the objdump of the binary, we notice that in the main function, 3 functions (x0, x1 and x2) are being called.

Before moving on, we decided to compare 2 different binaries to see how different they are. It seems like they are pretty similar, with only 12 instructions different, 4 each in x0, x1 and x2.

    $ diff 1.txt 2.txt
    2c2
    < 1.out:     file format elf64-x86-64
    ---
    > 2.out:     file format elf64-x86-64
    144,146c144,146
    <   4005f1:	c7 45 e0 08 00 00 00 	movl   $0x8,-0x20(%rbp)
    <   4005f8:	c7 45 e4 36 00 00 00 	movl   $0x36,-0x1c(%rbp)
    <   4005ff:	c7 45 e8 07 00 00 00 	movl   $0x7,-0x18(%rbp)
    ---
    >   4005f1:	c7 45 e0 33 00 00 00 	movl   $0x33,-0x20(%rbp)
    >   4005f8:	c7 45 e4 3f 00 00 00 	movl   $0x3f,-0x1c(%rbp)
    >   4005ff:	c7 45 e8 50 00 00 00 	movl   $0x50,-0x18(%rbp)
    164c164
    <   400642:	b8 eb 09 00 00       	mov    $0x9eb,%eax
    ---
    >   400642:	b8 7a 45 00 00       	mov    $0x457a,%eax
    183,185c183,185
    <   40067b:	c7 45 e0 1b 00 00 00 	movl   $0x1b,-0x20(%rbp)
    <   400682:	c7 45 e4 35 00 00 00 	movl   $0x35,-0x1c(%rbp)
    <   400689:	c7 45 e8 44 00 00 00 	movl   $0x44,-0x18(%rbp)
    ---
    >   40067b:	c7 45 e0 12 00 00 00 	movl   $0x12,-0x20(%rbp)
    >   400682:	c7 45 e4 44 00 00 00 	movl   $0x44,-0x1c(%rbp)
    >   400689:	c7 45 e8 4a 00 00 00 	movl   $0x4a,-0x18(%rbp)
    203c203
    <   4006cc:	b8 19 17 00 00       	mov    $0x1719,%eax
    ---
    >   4006cc:	b8 fc 37 00 00       	mov    $0x37fc,%eax
    222,224c222,224
    <   400705:	c7 45 e0 28 00 00 00 	movl   $0x28,-0x20(%rbp)
    <   40070c:	c7 45 e4 5e 00 00 00 	movl   $0x5e,-0x1c(%rbp)
    <   400713:	c7 45 e8 40 00 00 00 	movl   $0x40,-0x18(%rbp)
    ---
    >   400705:	c7 45 e0 15 00 00 00 	movl   $0x15,-0x20(%rbp)
    >   40070c:	c7 45 e4 05 00 00 00 	movl   $0x5,-0x1c(%rbp)
    >   400713:	c7 45 e8 1f 00 00 00 	movl   $0x1f,-0x18(%rbp)
    242c242
    <   400756:	b8 f0 1d 00 00       	mov    $0x1df0,%eax
    ---
    >   400756:	b8 f8 16 00 00       	mov    $0x16f8,%eax


Let's take a look at the disassembly of x0.

    00000000004005d6 <x0>:
      4005d6:	55                   	push   %rbp
      4005d7:	48 89 e5             	mov    %rsp,%rbp
      4005da:	48 83 ec 40          	sub    $0x40,%rsp
      4005de:	48 89 7d c8          	mov    %rdi,-0x38(%rbp)
      4005e2:	64 48 8b 04 25 28 00 	mov    %fs:0x28,%rax
      4005e9:	00 00 
      4005eb:	48 89 45 f8          	mov    %rax,-0x8(%rbp)
      4005ef:	31 c0                	xor    %eax,%eax
      4005f1:	c7 45 e0 08 00 00 00 	movl   $0x8,-0x20(%rbp)
      4005f8:	c7 45 e4 36 00 00 00 	movl   $0x36,-0x1c(%rbp)
      4005ff:	c7 45 e8 07 00 00 00 	movl   $0x7,-0x18(%rbp)
      400606:	c7 45 d8 00 00 00 00 	movl   $0x0,-0x28(%rbp)
      40060d:	c7 45 dc 00 00 00 00 	movl   $0x0,-0x24(%rbp)
      400614:	eb 26                	jmp    40063c <x0+0x66>
      400616:	8b 45 dc             	mov    -0x24(%rbp),%eax
      400619:	48 63 d0             	movslq %eax,%rdx
      40061c:	48 8b 45 c8          	mov    -0x38(%rbp),%rax
      400620:	48 01 d0             	add    %rdx,%rax
      400623:	0f b6 00             	movzbl (%rax),%eax
      400626:	0f be d0             	movsbl %al,%edx
      400629:	8b 45 dc             	mov    -0x24(%rbp),%eax
      40062c:	48 98                	cltq   
      40062e:	8b 44 85 e0          	mov    -0x20(%rbp,%rax,4),%eax
      400632:	0f af c2             	imul   %edx,%eax
      400635:	01 45 d8             	add    %eax,-0x28(%rbp)
      400638:	83 45 dc 01          	addl   $0x1,-0x24(%rbp)
      40063c:	83 7d dc 02          	cmpl   $0x2,-0x24(%rbp)
      400640:	7e d4                	jle    400616 <x0+0x40>
      400642:	b8 eb 09 00 00       	mov    $0x9eb,%eax
      400647:	2b 45 d8             	sub    -0x28(%rbp),%eax
      40064a:	48 8b 4d f8          	mov    -0x8(%rbp),%rcx
      40064e:	64 48 33 0c 25 28 00 	xor    %fs:0x28,%rcx
      400655:	00 00 
      400657:	74 05                	je     40065e <x0+0x88>
      400659:	e8 42 fe ff ff       	callq  4004a0 <__stack_chk_fail@plt>
      40065e:	c9                   	leaveq 
      40065f:	c3                   	retq   

Making sense of the assembly, we see some variables being initialised at 4005f1, 4005f8, and 4005ff (with values 0x8, 0x36 and 0x7 respectively in this example). Following that, there is a loop, where each of these values is multiplied with the value of each of the 3 characters of our input. The sum is then stored and compared with the value at 400642 (0x9eb in this example).

Looking at the other functions x1 and x2, we notice that the structure is similar, only with differences in the initialisation of variables and the final value being compared with. This also happens to be the diff in our objdump found above. Conveniently, the addresses are all the same, and so we assumed that the server generates binaries simply by changing these values.

Now, we craft our final script to solve this challenge. We use [pwntools](http://pwntools.com/) to handle the connection to the server, some regex to extract the values from the addresses that we found earlier, and [z3](https://github.com/Z3Prover/z3) to find a solution to the constraints.

    #!/usr/bin/python
    from pwn import *
    import base64
    from subprocess import Popen, PIPE, STDOUT
    import re
    from z3 import *

    r = remote('bg1.spro.ink', 4243)

    r.recvuntil('Go!\n\n')

    for i in xrange(50):
        log.info('Round %d'%i)

        s = r.recvline()

        t = base64.b64decode(s)

        with open('tmp', 'w') as f:
            f.write(t)

        p = Popen(['gobjdump', '-d', 'tmp'], stdout=PIPE)
        stdout_data = p.communicate()[0]

        m0 = re.search('4005f1:	c7 45 e0 ([0-9a-f]{2})', stdout_data)
        m1 = re.search('4005f8:	c7 45 e4 ([0-9a-f]{2})', stdout_data)
        m2 = re.search('4005ff:	c7 45 e8 ([0-9a-f]{2})', stdout_data)
        m3 = re.search('400642:	b8 ([0-9a-f]{2}) ([0-9a-f]{2})', stdout_data)

        # Constraints in x0
        x0a = int(m0.group(1), 16)
        x0b = int(m1.group(1), 16)
        x0c = int(m2.group(1), 16)
        x0d = int(m3.group(2) + m3.group(1), 16)

        m0 = re.search('40067b:	c7 45 e0 ([0-9a-f]{2})', stdout_data)
        m1 = re.search('400682:	c7 45 e4 ([0-9a-f]{2})', stdout_data)
        m2 = re.search('400689:	c7 45 e8 ([0-9a-f]{2})', stdout_data)
        m3 = re.search('4006cc:	b8 ([0-9a-f]{2}) ([0-9a-f]{2})', stdout_data)

        # Constraints in x1
        x1a = int(m0.group(1), 16)
        x1b = int(m1.group(1), 16)
        x1c = int(m2.group(1), 16)
        x1d = int(m3.group(2) + m3.group(1), 16)

        m0 = re.search('400705:	c7 45 e0 ([0-9a-f]{2})', stdout_data)
        m1 = re.search('40070c:	c7 45 e4 ([0-9a-f]{2})', stdout_data)
        m2 = re.search('400713:	c7 45 e8 ([0-9a-f]{2})', stdout_data)
        m3 = re.search('400756:	b8 ([0-9a-f]{2}) ([0-9a-f]{2})', stdout_data)

        # Constraints in x2
        x2a = int(m0.group(1), 16)
        x2b = int(m1.group(1), 16)
        x2c = int(m2.group(1), 16)
        x2d = int(m3.group(2) + m3.group(1), 16)

        # Input variables
        A = BitVec('A', 32)
        B = BitVec('B', 32)
        C = BitVec('C', 32)

        s = Solver()
        s.add(A*x0a+B*x0b+C*x0c == x0d,
            A*x1a+B*x1b+C*x1c == x1d,
            A*x2a+B*x2b+C*x2c == x2d,
            A <= 0xff, A >= 0,
            B <= 0xff, B >= 0,
            C <= 0xff, C >= 0)

        s.check()
        m = s.model()

        t = chr(m[A].as_long()) + chr(m[B].as_long()) + chr(m[C].as_long())

        log.info('Answer: %s' %t)
        r.send(t)

    r.interactive()


Running the script, we get the flag!

> Flag: XCTF{The\_Iris\_Welcomes\_You}
