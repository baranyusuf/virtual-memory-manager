#include "vmpagelib.h"
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>   // for uintptr_t


#define MAX_PROCESSES 4096
#define PAGE_SIZE 4096
#define MAX_FRAMES   (PHYS_MEM_SIZE / PAGE_SIZE)

typedef struct alloc_region {
    size_t start;               // byte offset within virtual space
    size_t size;                // length in bytes
    struct alloc_region* next;
} alloc_region_t;

typedef struct free_region {
    size_t start;
    size_t size;
    struct free_region* next;
} free_region_t;

typedef struct {
    bool            created;
    free_region_t*  free_list;
    alloc_region_t* alloc_list;
    int*            page_table;    // length = MAX_FRAMES, -1 = unmapped
} process_t;

// Global state
static process_t processes[MAX_PROCESSES];
static unsigned char physical_memory[PHYS_MEM_SIZE];
static int free_frames[MAX_FRAMES];
static int free_frame_count;

VMStatus vm_page_init() {
    // 1) Initialize free-frame stack
    for (int i = 0; i < MAX_FRAMES; i++) {
        free_frames[i] = i;
    }
    free_frame_count = MAX_FRAMES;

    // 2) Clear physical memory
    memset(physical_memory, 0, PHYS_MEM_SIZE);

    // 3) Reset all process control blocks
    for (int pid = 0; pid < MAX_PROCESSES; pid++) {
        processes[pid].created    = false;
        processes[pid].free_list  = NULL;
        processes[pid].alloc_list = NULL;
        processes[pid].page_table = NULL;
    }

    return VM_OK;
}

VMStatus vm_page_create_process(int pid) {
    // 1) Check PID validity and not previously created
    if (pid < 0 || pid >= MAX_PROCESSES || processes[pid].created) {
        return VM_INVALID_PID;
    }

    // 2) Allocate & initialize the page table: 2^20 entries for 32-bit VA with 4KB pages
    size_t num_pages = (size_t)1 << (32 - 12);  // 2^(32−offset_bits), offset_bits=12 for 4096B pages
    processes[pid].page_table = malloc(num_pages * sizeof(int));

    for (size_t i = 0; i < num_pages; i++) {
        processes[pid].page_table[i] = -1;  // unmapped
    }

    // 3) Initialize the free_list to cover [0 … 2^32) in one region
    free_region_t* r = malloc(sizeof(free_region_t));
    r->start = 0;
    r->size  = num_pages * PAGE_SIZE;  // entire virtual space
    r->next  = NULL;

    // 4) Set up control block
    processes[pid].free_list  = r;
    processes[pid].alloc_list = NULL;
    processes[pid].created    = true;

    return VM_OK;
}

VMStatus vm_page_alloc(int pid, size_t size, void **virtual_addr) {
    // 1) PID must be valid and created
    if (pid < 0 || pid >= MAX_PROCESSES || !processes[pid].created) {
        return VM_INVALID_PID;
    }
    // 2) Zero‐size alloc: return NULL
    if (size == 0) {
        *virtual_addr = NULL;
        return VM_OK;
    }

    // 3) Find first‐fit free region
    free_region_t *cur = processes[pid].free_list;
    free_region_t *prev = NULL;
    while (cur && cur->size < size) {
        prev = cur;
        cur  = cur->next;
    }
    if (!cur) {
        return VM_NOT_ENOUGH_MEMORY;
    }

    // 4) Compute which pages this allocation will cover
    size_t alloc_start = cur->start;
    size_t start_page  = alloc_start / PAGE_SIZE;
    size_t end_page    = (alloc_start + size - 1) / PAGE_SIZE;

    // 5) Count how many *new* frames we must allocate
    size_t pages_needed = 0;
    for (size_t p = start_page; p <= end_page; p++) {
        if (processes[pid].page_table[p] == -1) {
            pages_needed++;
        }
    }
    if (free_frame_count < (int)pages_needed) {
        return VM_NOT_ENOUGH_MEMORY;
    }

    // 6) Carve out the free_region
    cur->start += size;
    cur->size  -= size;
    if (cur->size == 0) {
        if (prev) prev->next = cur->next;
        else        processes[pid].free_list = cur->next;
        free(cur);
    }

    // 7) Record this allocation in alloc_list
    alloc_region_t *a = malloc(sizeof(*a));
    a->start = alloc_start;
    a->size  = size;
    a->next  = processes[pid].alloc_list;
    processes[pid].alloc_list = a;

    // 8) Allocate any pages not yet mapped
    for (size_t p = start_page; p <= end_page; p++) {
        if (processes[pid].page_table[p] == -1) {
            // pop one frame
            free_frame_count--;
            int frame = free_frames[free_frame_count];
            processes[pid].page_table[p] = frame;
        }
    }

    // 9) Return the base virtual address
    *virtual_addr = (void*)(uintptr_t)alloc_start;
    return VM_OK;
}

VMStatus vm_page_free(int pid, void* virtual_addr) {
    // 1) PID validity
    if (pid < 0 || pid >= MAX_PROCESSES || !processes[pid].created) {
        return VM_INVALID_PID;
    }

    // 2) Find the alloc_region with matching start address
    size_t addr = (size_t)(uintptr_t)virtual_addr;
    alloc_region_t *prev_a = NULL, *cur_a = processes[pid].alloc_list;
    while (cur_a && cur_a->start != addr) {
        prev_a = cur_a;
        cur_a  = cur_a->next;
    }
    if (!cur_a) {
        // no allocation beginning at this address
        return VM_INVALID_ADDRESS;
    }
    size_t size = cur_a->size;

    // 3) Remove this alloc_region from the list
    if (prev_a) prev_a->next = cur_a->next;
    else        processes[pid].alloc_list = cur_a->next;
    free(cur_a);

    // 4) For each page in [addr, addr+size), free the frame if no other alloc covers it
    size_t start_page = addr / PAGE_SIZE;
    size_t end_page   = (addr + size - 1) / PAGE_SIZE;
    for (size_t p = start_page; p <= end_page; p++) {
        int frame = processes[pid].page_table[p];
        if (frame == -1) continue;  // already unmapped (shouldn't happen)

        // check if any other allocation still uses this page
        bool in_use = false;
        alloc_region_t *scan = processes[pid].alloc_list;
        size_t page_start = p * PAGE_SIZE;
        size_t page_end   = page_start + PAGE_SIZE; // one past last byte
        while (scan) {
            size_t a0 = scan->start;
            size_t a1 = a0 + scan->size;
            // overlap if [a0,a1) intersects [page_start, page_end)
            if (a0 < page_end && a1 > page_start) {
                in_use = true;
                break;
            }
            scan = scan->next;
        }
        if (!in_use) {
            // push frame back onto free stack
            free_frames[free_frame_count++] = frame;
            processes[pid].page_table[p] = -1;
        }
    }

    // 5) Insert the freed region back into the free_list (sorted by address),
    //    then coalesce with adjacent holes if contiguous.
    free_region_t *prev_f = NULL, *cur_f = processes[pid].free_list;
    // find insert point: first region with start > addr
    while (cur_f && cur_f->start < addr) {
        prev_f = cur_f;
        cur_f  = cur_f->next;
    }
    // create new hole node
    free_region_t *new_hole = malloc(sizeof(*new_hole));
    new_hole->start = addr;
    new_hole->size  = size;
    new_hole->next  = cur_f;
    if (prev_f) prev_f->next = new_hole;
    else        processes[pid].free_list = new_hole;

    // coalesce with previous if adjacent
    if (prev_f) {
        size_t prev_end = prev_f->start + prev_f->size;
        if (prev_end == new_hole->start) {
            prev_f->size += new_hole->size;
            prev_f->next  = new_hole->next;
            free(new_hole);
            new_hole = prev_f;
        }
    }
    // coalesce with next if adjacent
    if (new_hole->next) {
        size_t hole_end = new_hole->start + new_hole->size;
        if (hole_end == new_hole->next->start) {
            free_region_t *to_merge = new_hole->next;
            new_hole->size += to_merge->size;
            new_hole->next  = to_merge->next;
            free(to_merge);
        }
    }

    return VM_OK;
}

VMStatus vm_page_translate(int pid, void* virtual_addr, void** physical_addr) {
    // 1) PID validity
    if (pid < 0 || pid >= MAX_PROCESSES || !processes[pid].created) {
        return VM_INVALID_PID;
    }

    // 2) Ensure virtual_addr lies within a previously allocated region
    size_t addr = (size_t)(uintptr_t)virtual_addr;
    alloc_region_t *scan = processes[pid].alloc_list;
    while (scan) {
        if (addr >= scan->start && addr < scan->start + scan->size) {
            break;
        }
        scan = scan->next;
    }
    if (!scan) {
        return VM_INVALID_ADDRESS;
    }

    // 3) Compute page number and offset
    size_t page   = addr / PAGE_SIZE;
    size_t offset = addr % PAGE_SIZE;

    // 4) Check that this page is mapped
    int frame = processes[pid].page_table[page];
    if (frame == -1) {
        return VM_INVALID_ADDRESS;
    }

    // 5) Compute the physical address and return it
    *physical_addr = (void*)&physical_memory[frame * PAGE_SIZE + offset];
    return VM_OK;
}


VMStatus vm_page_write(int pid,
                       void* virtual_addr,
					   const void* write_data,
                       size_t size)
{

	const unsigned char *src = write_data;

    // 1) PID validity
    if (pid < 0 || pid >= MAX_PROCESSES || !processes[pid].created) {
        return VM_INVALID_PID;
    }

    // 2) Nothing to do for zero‐length write
    if (size == 0) {
        return VM_OK;
    }

    size_t addr = (size_t)(uintptr_t)virtual_addr;

    // 3) Find the allocation region that contains the start address
    alloc_region_t *region = processes[pid].alloc_list;
    while (region) {
        if (addr >= region->start
         && addr <  region->start + region->size) {
            break;
        }
        region = region->next;
    }
    if (!region) {
        // start address not in any allocation
        return VM_INVALID_ADDRESS;
    }

    // 4) Ensure the entire [addr, addr+size) lies within that same region
    if (addr + size > region->start + region->size) {
        return VM_INVALID_RANGE;
    }

    // 5) Perform the write, page by page
    size_t remaining = size;
    size_t cur_addr  = addr;
    size_t data_off  = 0;

    while (remaining > 0) {
        size_t page        = cur_addr / PAGE_SIZE;
        size_t page_offset = cur_addr % PAGE_SIZE;

        // Must be mapped
        int frame = processes[pid].page_table[page];
        if (frame == -1) {
            return VM_INVALID_ACCESS;
        }

        // How many bytes to write in this page
        size_t chunk = PAGE_SIZE - page_offset;
        if (chunk > remaining) {
            chunk = remaining;
        }

        // Copy into physical memory
        memcpy(&physical_memory[frame * PAGE_SIZE + page_offset],
        		src + data_off,
               chunk);

        // Advance
        remaining -= chunk;
        cur_addr    += chunk;
        data_off    += chunk;
    }

    return VM_OK;
}

VMStatus vm_page_read(int pid,
                      void* virtual_addr,
					  void* read_buffer,
                      size_t size)
{

	unsigned char *dst = read_buffer;
    // 1) PID validity
    if (pid < 0 || pid >= MAX_PROCESSES || !processes[pid].created) {
        return VM_INVALID_PID;
    }

    // 2) Zero‐length reads always succeed
    if (size == 0) {
        return VM_OK;
    }

    size_t addr = (size_t)(uintptr_t)virtual_addr;

    // 3) Find the allocation region containing the start
    alloc_region_t *region = processes[pid].alloc_list;
    while (region) {
        if (addr >= region->start
         && addr <  region->start + region->size) {
            break;
        }
        region = region->next;
    }
    if (!region) {
        // start address not in any allocation
        return VM_INVALID_ADDRESS;
    }

    // 4) Ensure [addr, addr+size) lies within that same region
    if (addr + size > region->start + region->size) {
        return VM_INVALID_RANGE;
    }

    // 5) Perform the read, page by page
    size_t remaining = size;
    size_t cur_addr  = addr;
    size_t buf_off   = 0;

    while (remaining > 0) {
        size_t page        = cur_addr / PAGE_SIZE;
        size_t page_offset = cur_addr % PAGE_SIZE;

        // Must be mapped
        int frame = processes[pid].page_table[page];
        if (frame == -1) {
            return VM_INVALID_ACCESS;
        }

        // How many bytes to read in this page
        size_t chunk = PAGE_SIZE - page_offset;
        if (chunk > remaining) {
            chunk = remaining;
        }

        // Copy out of physical memory
        memcpy(dst + buf_off,
               &physical_memory[frame * PAGE_SIZE + page_offset],
               chunk);

        // Advance pointers
        remaining -= chunk;
        cur_addr    += chunk;
        buf_off     += chunk;
    }

    return VM_OK;
}

VMStatus vm_page_phys_mem_print(const char* file_name) {
    // 1) Open output file
    FILE *fp = fopen(file_name, "w");
    if (!fp) {
        // Could not create file
        return VM_NOT_ENOUGH_MEMORY;
    }

    // 2) For each physical frame, print either “-1 -1” if free,
    //    or “PID PAGE_NUMBER” if in use.
    for (int frame = 0; frame < MAX_FRAMES; frame++) {
        // Check if frame is still in the free‐frame stack
        bool is_free = false;
        for (int i = 0; i < free_frame_count; i++) {
            if (free_frames[i] == frame) {
                is_free = true;
                break;
            }
        }
        if (is_free) {
            // Unused frame
            fprintf(fp, "-1 -1\n");
            continue;
        }

        // Otherwise, find which process and which virtual page maps here
        bool found = false;
        // Number of virtual pages = 2^(32−12)
        size_t num_pages = (size_t)1 << (32 - 12);
        for (int pid = 0; pid < MAX_PROCESSES && !found; pid++) {
            if (!processes[pid].created) {
                continue;
            }
            // Scan this process’s page table
            for (size_t vpn = 0; vpn < num_pages; vpn++) {
                if (processes[pid].page_table[vpn] == frame) {
                    // Found mapping
                    fprintf(fp, "%u %zu\n", pid, vpn);
                    found = true;
                    break;
                }
            }
        }
        if (!found) {
            // Should not happen, but treat as free
            fprintf(fp, "-1 -1\n");
        }
    }

    // 3) Clean up
    fclose(fp);
    return VM_OK;
}

VMStatus vm_page_cleanup() {
    // Iterate over all processes and free their dynamic resources
    for (int pid = 0; pid < MAX_PROCESSES; pid++) {
        if (!processes[pid].created) continue;

        // 1) Free the page table
        free(processes[pid].page_table);
        processes[pid].page_table = NULL;

        // 2) Free the free‐region list
        free_region_t *fcur = processes[pid].free_list;
        while (fcur) {
            free_region_t *fnext = fcur->next;
            free(fcur);
            fcur = fnext;
        }
        processes[pid].free_list = NULL;

        // 3) Free the alloc‐region list
        alloc_region_t *acur = processes[pid].alloc_list;
        while (acur) {
            alloc_region_t *anext = acur->next;
            free(acur);
            acur = anext;
        }
        processes[pid].alloc_list = NULL;

        // 4) Mark process as not created
        processes[pid].created = false;
    }

    // Note: physical_memory and free_frames are static arrays;
    // we simply reset the free‐frame count to zero to reflect
    // that no frames are currently “in use” of dynamically tracked ones.
    free_frame_count = 0;

    return VM_OK;
}
