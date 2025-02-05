.data
	wSsn DWORD 0h
	qSyscallRet QWORD 0h

.code 
	sysPrepare PROC
		mov wSsn, 000h
		mov wSsn, ecx
		mov rax, rdx           ; Store function address (syscall stub)
        mov qSyscallRet, rax
		ret
	sysPrepare ENDP

	sysExec PROC
		mov r10, rcx
		mov eax, wSsn
		jmp qword ptr [qSyscallRet]
		ret
	sysExec ENDP

	sysNtOpenProcess PROC
		mov r10, rcx
		mov eax, wSsn
		syscall
		ret
	sysNtOpenProcess ENDP

	sysNtAllocateVirtualMem PROC
		mov r10, rcx
		mov eax, wSsn

		syscall
		ret
	sysNtAllocateVirtualMem ENDP

	sysNtWriteVirtualMem PROC
		mov r10, rcx
		mov eax, wSsn

		syscall
		ret
	sysNtWriteVirtualMem ENDP

	sysNtProtectVirtualMem PROC
		mov r10, rcx
		mov eax, wSsn

		syscall
		ret
	sysNtProtectVirtualMem ENDP

	sysNtCreateThreadEx PROC
		mov r10, rcx
		mov eax, wSsn

		syscall
		ret
	sysNtCreateThreadEx ENDP

	sysNtWaitForSingleObject PROC
		mov r10, rcx
		mov eax, wSsn

		syscall
		ret
	sysNtWaitForSingleObject ENDP
end