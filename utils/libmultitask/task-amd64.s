/* sysv amd64 abi:
 * integer arguments 1-6 in RDI, RSI, RDX, RCX, R8, R9
 * integer arguments 7- on the stack
 * return value in RAX
 * RBP, RBX, R12-R15 are callee save
 */

.global _tasksetjmp
.type _tasksetjmp,@function
/* void _tasksetjmp(jmp_buf env, void *stack, Task *t) */
_tasksetjmp:
    /* save stack pointer */
    PUSH RBX
    MOV RBX, RSP
    /* switch to new stack */
    MOV RSP, RSI
    /* push arguments to new stack */
    PUSH RDX
    /* save context with setjmp (RDI still contains env) */
    CALL setjmp
    TEST RAX, RAX
    JZ rval
    /* entering thread for the first time */
    MOV RDI, QWORD PTR [RSP] /* t */
    MOV QWORD PTR [RSP], 0 /* end of frame */
    MOV RBP, 0 /* frame pointer if used */
    JMP _taskstart

rval:
    /* restore stack pointer and return */
    MOV RSP, RBX
    POP RBX
    RET

.global _taskspin
.type _taskspin,@function
/* void _taskspin(void) */
_taskspin:
    PAUSE
    RET
