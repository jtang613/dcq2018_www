# dcq2018_www
### Defcon 2018 Qualifiers - WWW Solution

The vulnerability exists in the function HTParseInet, HTTPC.c:185
```
char host[256];
////
strcpy(host, str); /* Take a copy we can mutilate */
```

This exploit overflows 'host' to redirect the return address to our shellcode on the stack. This shellcode in turn, sets up the stack with the local path to the flag 'file:///me/flag' and calls into HTOpenFile to return a file descriptor (rather than the expected socket). Since the eventual read() call is agnostic to whether it's reading a file descriptor or socket, we can now read and display the local file in the browser window.  A little bit of stack and variable massaging ensures enough stability to execute without crashing.

The important constraint on the shellcode is there must be no '#', ':', '/' or null characters for it to deliver successfully.


![Screenshot](/screenshot.png?raw=true "Pwnd")

