# virtual-memory-manager

## Overview
This project implements a **Memory Management Library** in C that simulates how an operating system manages virtual memory.  
Two approaches are supported:
- **Single-Layer Page Table**
- **Inverted Page Table**

The system uses a mock physical memory (byte array), and each process is assigned its own 32-bit virtual address space.

---

## Features
- **Process Management**
  - `vm_page_create_process(pid)` and `vm_invpage_create_process(pid)` allow registering processes with unique 12-bit PIDs.  

- **Allocation & Freeing**
  - Allocate memory (`vm_page_alloc`, `vm_invpage_alloc`)  
  - Free allocated blocks (`vm_page_free`, `vm_invpage_free`)  

- **Address Translation**
  - Translate virtual to physical addresses.  

- **Read & Write**
  - Read/write bytes in virtual memory that map to physical memory.  

- **Physical Memory Inspection**
  - Export physical memory state to a file for debugging.  

- **Cleanup**
  - Deallocate and reset all structures when finished.

---
