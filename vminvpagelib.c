#include "vminvpagelib.h"
#include <stdlib.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

#define PAGE_SIZE   4096                                ///< 4 KB pages
#define MAX_FRAMES  (PHYS_MEM_SIZE / PAGE_SIZE)         ///< Maximum number of frames
#define MAX_PROCESSES 4096

// Compute total virtual space (32-bit): 2^32 bytes
#define NUM_VPAGES   ((size_t)1 << (32 - 12))           ///< number of 4KB pages in 4GB
#define VIRTUAL_SPACE_SIZE (NUM_VPAGES * PAGE_SIZE)     ///< 4GB per process

// -- Per-process free/alloc lists ------------------------------------------
typedef struct free_region {
    size_t start, size;
    struct free_region *next;
} free_region_t;

typedef struct alloc_region {
    size_t start, size;
    struct alloc_region *next;
} alloc_region_t;

static free_region_t  *free_list[MAX_PROCESSES];
static alloc_region_t *alloc_list[MAX_PROCESSES];
static bool            pid_created[MAX_PROCESSES];

// -- Inverted page table & physical memory ----------------------------------
typedef struct {
    int pid;    ///< owning process ID, -1 if free
    int vpn;    ///< virtual page number within process
} invpage_entry_t;

static invpage_entry_t inv_page_table[MAX_FRAMES];
static unsigned char   physical_memory[PHYS_MEM_SIZE];

// -- Free-frame stack -------------------------------------------------------
static int free_frames[MAX_FRAMES];
static int free_frame_count;

//----------------------------------------------------------------------
// Initialize the inverted-page-table VMM
//----------------------------------------------------------------------
VMStatus vm_invpage_init() {
    // 1) Reset process tables
    for (int pid = 0; pid < MAX_PROCESSES; pid++) {
        pid_created[pid]  = false;
        free_list[pid]    = NULL;
        alloc_list[pid]   = NULL;
    }
    // 2) Initialize free-frame stack
    for (int f = 0; f < MAX_FRAMES; f++) {
        free_frames[f] = f;
    }
    free_frame_count = MAX_FRAMES;
    // 3) Mark all inverted-table entries free
    for (int f = 0; f < MAX_FRAMES; f++) {
        inv_page_table[f].pid = -1;
        inv_page_table[f].vpn = -1;
    }
    // 4) Clear physical memory
    memset(physical_memory, 0, sizeof(physical_memory));
    return VM_OK;
}

//----------------------------------------------------------------------
// Create a new process (initialize its free/alloc lists)
//----------------------------------------------------------------------
VMStatus vm_invpage_create_process(int pid) {
    if (pid < 0 || pid >= MAX_PROCESSES || pid_created[pid]) {
        return VM_INVALID_PID;
    }
    // One big free region covering entire 4GB address space
    free_region_t *r = malloc(sizeof(*r));
    if (!r) return VM_NOT_ENOUGH_MEMORY;
    r->start = 0;
    r->size  = VIRTUAL_SPACE_SIZE;
    r->next  = NULL;
    free_list[pid]  = r;
    alloc_list[pid] = NULL;
    pid_created[pid] = true;
    return VM_OK;
}

//----------------------------------------------------------------------
// Allocate `size` bytes for `pid`, return virtual address (offset)
//----------------------------------------------------------------------
VMStatus vm_invpage_alloc(int pid, size_t size, void **virtual_addr) {
    if (pid < 0 || pid >= MAX_PROCESSES || !pid_created[pid])
        return VM_INVALID_PID;
    if (size == 0) {
        *virtual_addr = NULL;
        return VM_OK;
    }
    // How many pages needed?
    size_t num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    if ((int)num_pages > free_frame_count)
        return VM_NOT_ENOUGH_MEMORY;

    // Find first-fit free region
    free_region_t *prev = NULL, *cur = free_list[pid];
    while (cur && cur->size < size) {
        prev = cur; cur = cur->next;
    }
    if (!cur) return VM_NOT_ENOUGH_MEMORY;

    // Carve out region
    size_t alloc_start = cur->start;
    cur->start += size;
    cur->size  -= size;
    if (cur->size == 0) {
        if (prev) prev->next = cur->next;
        else      free_list[pid] = cur->next;
        free(cur);
    }
    // Record allocation
    alloc_region_t *a = malloc(sizeof(*a));
    if (!a) return VM_NOT_ENOUGH_MEMORY;
    a->start = alloc_start;
    a->size  = size;
    a->next  = alloc_list[pid];
    alloc_list[pid] = a;

    // Assign physical frames
    size_t start_vpn = alloc_start / PAGE_SIZE;
    for (size_t i = 0; i < num_pages; i++) {
        int frame = free_frames[--free_frame_count];
        inv_page_table[frame].pid = pid;
        inv_page_table[frame].vpn = start_vpn + i;
    }
    // Return virtual address (offset)
    *virtual_addr = (void*)(uintptr_t)alloc_start;
    return VM_OK;
}

//----------------------------------------------------------------------
// Free a previously allocated block
//----------------------------------------------------------------------
VMStatus vm_invpage_free(int pid, void *virtual_addr) {
    if (pid < 0 || pid >= MAX_PROCESSES || !pid_created[pid])
        return VM_INVALID_PID;
    size_t offset = (size_t)(uintptr_t)virtual_addr;
    // Find matching alloc_region
    alloc_region_t *prev_a = NULL, *ar = alloc_list[pid];
    while (ar && ar->start != offset) {
        prev_a = ar; ar = ar->next;
    }
    if (!ar) return VM_INVALID_ADDRESS;
    size_t size = ar->size;
    // Remove from alloc_list
    if (prev_a) prev_a->next = ar->next;
    else        alloc_list[pid] = ar->next;
    free(ar);

    // Release frames if unused
    size_t vpn0      = offset / PAGE_SIZE;
    size_t num_pages = (size + PAGE_SIZE - 1) / PAGE_SIZE;
    for (size_t i = 0; i < num_pages; i++) {
        int target_vpn = vpn0 + i;
        // find frame for (pid, vpn)
        for (int f = 0; f < MAX_FRAMES; f++) {
            if (inv_page_table[f].pid == pid &&
                inv_page_table[f].vpn == target_vpn) {
                // check other allocs
                bool in_use = false;
                for (alloc_region_t *r = alloc_list[pid]; r; r = r->next) {
                    size_t lo = r->start;
                    size_t hi = lo + r->size;
                    size_t page_lo = target_vpn * PAGE_SIZE;
                    if (page_lo < hi && (page_lo + PAGE_SIZE) > lo) {
                        in_use = true;
                        break;
                    }
                }
                if (!in_use) {
                    inv_page_table[f].pid = -1;
                    inv_page_table[f].vpn = -1;
                    free_frames[free_frame_count++] = f;
                }
                break;
            }
        }
    }

    // Reinsert free region and coalesce
    free_region_t *prev_f = NULL, *fr = free_list[pid];
    while (fr && fr->start < offset) {
        prev_f = fr; fr = fr->next;
    }
    free_region_t *new_h = malloc(sizeof(*new_h));
    if (!new_h) return VM_NOT_ENOUGH_MEMORY;
    new_h->start = offset;
    new_h->size  = size;
    new_h->next  = fr;
    if (prev_f) prev_f->next = new_h;
    else         free_list[pid] = new_h;
    // coalesce next
    if (new_h->next && new_h->start + new_h->size == new_h->next->start) {
        free_region_t *nx = new_h->next;
        new_h->size += nx->size;
        new_h->next  = nx->next;
        free(nx);
    }
    // coalesce prev
    if (prev_f && prev_f->start + prev_f->size == new_h->start) {
        prev_f->size += new_h->size;
        prev_f->next  = new_h->next;
        free(new_h);
    }
    return VM_OK;
}

//----------------------------------------------------------------------
// Translate a virtual offset to physical address
//----------------------------------------------------------------------
VMStatus vm_invpage_translate(int pid, void *virtual_addr, void **physical_addr) {
    if (pid < 0 || pid >= MAX_PROCESSES || !pid_created[pid])
        return VM_INVALID_PID;
    size_t offset = (size_t)(uintptr_t)virtual_addr;
    // Check within an alloc
    alloc_region_t *r = alloc_list[pid];
    while (r) {
        if (offset >= r->start && offset < r->start + r->size)
            break;
        r = r->next;
    }
    if (!r) return VM_INVALID_ADDRESS;
    size_t vpn    = offset / PAGE_SIZE;
    size_t off    = offset % PAGE_SIZE;
    // find frame
    for (int f = 0; f < MAX_FRAMES; f++) {
        if (inv_page_table[f].pid == pid && inv_page_table[f].vpn == (int)vpn) {
            *physical_addr = &physical_memory[f * PAGE_SIZE + off];
            return VM_OK;
        }
    }
    return VM_INVALID_ADDRESS;
}

//----------------------------------------------------------------------
// Write to virtual memory
//----------------------------------------------------------------------
VMStatus vm_invpage_write(int pid, void *virtual_addr,
		const void* write_data, size_t size) {
	const unsigned char *src = write_data;

    if (pid < 0 || pid >= MAX_PROCESSES || !pid_created[pid])
        return VM_INVALID_PID;
    if (size == 0) return VM_OK;
    size_t addr = (size_t)(uintptr_t)virtual_addr;
    // find alloc region
    alloc_region_t *r = alloc_list[pid];
    while (r) {
        if (addr >= r->start && addr + size <= r->start + r->size)
            break;
        r = r->next;
    }
    if (!r) return (addr < r->start || addr >= r->start + r->size)
                   ? VM_INVALID_ADDRESS : VM_INVALID_RANGE;
    // copy page by page
    size_t rem = size;
    size_t cur = addr;
    size_t offw=0;
    while (rem) {
        size_t vpn = cur / PAGE_SIZE;
        size_t po  = cur % PAGE_SIZE;
        // find frame
        int frame = -1;
        for (int f = 0; f < MAX_FRAMES; f++) {
            if (inv_page_table[f].pid == pid && inv_page_table[f].vpn == (int)vpn) {
                frame = f; break;
            }
        }
        if (frame < 0) return VM_INVALID_ACCESS;
        size_t chunk = PAGE_SIZE - po;
        if (chunk > rem) chunk = rem;
        memcpy(physical_memory + frame*PAGE_SIZE + po,
        		src + offw, chunk);
        rem -= chunk;
        cur += chunk;
        offw+= chunk;
    }
    return VM_OK;
}

//----------------------------------------------------------------------
// Read from virtual memory
//----------------------------------------------------------------------
VMStatus vm_invpage_read(int pid, void *virtual_addr,
		void*read_buffer, size_t size) {

	unsigned char *dst = read_buffer;

    if (pid < 0 || pid >= MAX_PROCESSES || !pid_created[pid])
        return VM_INVALID_PID;
    if (size == 0) return VM_OK;
    size_t addr = (size_t)(uintptr_t)virtual_addr;
    alloc_region_t *r = alloc_list[pid];
    while (r) {
        if (addr >= r->start && addr + size <= r->start + r->size)
            break;
        r = r->next;
    }
    if (!r) return (addr < r->start || addr >= r->start + r->size)
                   ? VM_INVALID_ADDRESS : VM_INVALID_RANGE;
    size_t rem = size;
    size_t cur = addr;
    size_t offr=0;
    while (rem) {
        size_t vpn = cur / PAGE_SIZE;
        size_t po  = cur % PAGE_SIZE;
        int frame = -1;
        for (int f = 0; f < MAX_FRAMES; f++) {
            if (inv_page_table[f].pid == pid && inv_page_table[f].vpn == (int)vpn) {
                frame = f; break;
            }
        }
        if (frame < 0) return VM_INVALID_ACCESS;
        size_t chunk = PAGE_SIZE - po;
        if (chunk > rem) chunk = rem;
        memcpy(dst + offr,
               physical_memory + frame*PAGE_SIZE + po,
               chunk);
        rem -= chunk;
        cur += chunk;
        offr+= chunk;
    }
    return VM_OK;
}

//----------------------------------------------------------------------
// Dump frame-to-(pid,vpn) map to file
//----------------------------------------------------------------------
VMStatus vm_invpage_phys_mem_print(const char* file_name) {
    FILE *fp = fopen(file_name, "w");
    if (!fp) return VM_NOT_ENOUGH_MEMORY;
    for (int f = 0; f < MAX_FRAMES; f++) {
        if (inv_page_table[f].pid < 0) {
            fprintf(fp, "-1 -1\n");
        } else {
            fprintf(fp, "%d %d\n",
                    inv_page_table[f].pid,
                    inv_page_table[f].vpn);
        }
    }
    fclose(fp);
    return VM_OK;
}

//----------------------------------------------------------------------
// Cleanup all state
//----------------------------------------------------------------------
VMStatus vm_invpage_cleanup() {
    // Free per-process lists
    for (int pid = 0; pid < MAX_PROCESSES; pid++) {
        if (!pid_created[pid]) continue;
        // free free_list
        free_region_t *f = free_list[pid];
        while (f) {
            free_region_t *n = f->next;
            free(f);
            f = n;
        }
        // free alloc_list
        alloc_region_t *a = alloc_list[pid];
        while (a) {
            alloc_region_t *n = a->next;
            free(a);
            a = n;
        }
        pid_created[pid]  = false;
        free_list[pid]    = NULL;
        alloc_list[pid]   = NULL;
    }
    // reset frame stack
    free_frame_count = 0;
    return VM_OK;
}
