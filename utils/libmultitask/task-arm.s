/*
 * ARM ABI:
 * a1-a4 are arguments (clobbered, caller-save)
 * v1-v6 are callee-save
 * a1 is return value
 */

.global _tasksetjmp
.type _tasksetjmp,%function
/* void _tasksetjmp(jmp_buf env, void *stack, Task *t) */
_tasksetjmp:
    /* save stack pointer */
    push {v1, v2, lr}
    mov v1, sp
    /* switch to new stack */
    mov sp, a2
    /* save argument t in v2 */
    mov v2, a3
    /* save context with setjmp (a1 still contains env) */
    bl setjmp
    cmp a1, #0
    beq rval
    /* entering thread for the first time */
    mov a1, v2
    b _taskstart

rval:
    /* restore sp, registers and return */
    mov sp, v1
    pop {v1, v2, lr}
    tst lr, #1
    moveq pc, lr
    bx lr

.global _taskspin
.type _taskspin,%function
/* void _taskspin(void) */
_taskspin:
    tst lr, #1
    moveq pc, lr
    bx lr
