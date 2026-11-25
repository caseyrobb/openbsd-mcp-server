//go:build openbsd && (amd64 || arm64)

#include "textflag.h"

TEXT libc_sendsyslog_trampoline<>(SB),NOSPLIT,$0-0
	JMP	libc_sendsyslog(SB)
GLOBL	·libc_sendsyslog_trampoline_addr(SB), RODATA, $8
DATA	·libc_sendsyslog_trampoline_addr(SB)/8, $libc_sendsyslog_trampoline<>(SB)
