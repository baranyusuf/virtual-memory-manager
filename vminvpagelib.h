#pragma once
#include <stddef.h>

#define PAGE_SIZE 4096                              ///< 4 KB pages
#define MAX_FRAMES (PHYS_MEM_SIZE / PAGE_SIZE)      ///< Maximum number of frames

#ifndef VMSTATUS_TYPEDEF
#define VMSTATUS_TYPEDEF

/**
 * @enum VMStatus
 * @brief Defines the possible status codes that can be returned by the virtual memory manager (VMM) functions.
 */
typedef enum {
    VM_OK,                  ///< Operation completed successfully.
    VM_NOT_ENOUGH_MEMORY,   ///< Not enough memory available.
    VM_INVALID_RANGE,       ///< Invalid memory address range.
    VM_INVALID_ADDRESS,     ///< Invalid memory address.
    VM_INVALID_PID,         ///< Invalid process ID.
    VM_INVALID_ACCESS       ///< Invalid memory access.
} VMStatus;

#endif

/**
 * @brief Initializes the virtual memory manager (VMM).
 * 
 * @return VMStatus Indicates the success or failure of the initialization process.
 */
VMStatus vm_invpage_init();

/**
 * @brief Creates a new process with a given process ID (pid).
 * 
 * @param pid Process ID of the new process.
 * @return VMStatus Indicates the success or failure of the process creation.
 */
VMStatus vm_invpage_create_process(int pid);

/**
 * @brief Allocates a specified size of memory for a given process ID (pid).
 * 
 * @param pid Process ID for which memory is allocated.
 * @param size Size of memory to allocate.
 * @param virtual_addr Pointer to store the start address of the allocated virtual memory space.
 * @return VMStatus Indicates the success or failure of the memory allocation process.
 */
VMStatus vm_invpage_alloc(int pid, size_t size, void** virtual_addr);

/**
 * @brief Frees a previously allocated memory block for a given process ID (pid).
 * 
 * @param pid Process ID for which memory is freed.
 * @param virtual_addr Virtual address of the memory block to free.
 * @return VMStatus Indicates the success or failure of the memory deallocation process.
 */
VMStatus vm_invpage_free(int pid, void* virtual_addr);

/**
 * @brief Translates a virtual address to a physical address for a given process ID (pid).
 * 
 * @param pid Process ID for which the translation is performed.
 * @param virtual_addr Virtual address to translate.
 * @param physical_addr Pointer to store the resulting physical address.
 * @return VMStatus Indicates the success or failure of the translation process.
 */
VMStatus vm_invpage_translate(int pid, void* virtual_addr, void** physical_addr);

/**
 * @brief Writes data to a specified virtual address for a given process ID (pid).
 * 
 * @param pid Process ID for which the write operation is performed.
 * @param virtual_addr Virtual address to write to.
 * @param write_data Array containing the data to write.
 * @param size Number of bytes to write.
 * @return VMStatus Indicates the success or failure of the write operation.
 */
VMStatus vm_invpage_write(int pid, void* virtual_addr, const void* write_data, size_t size);

/**
 * @brief Reads data from a specified virtual address for a given process ID (pid).
 * 
 * @param pid Process ID for which the read operation is performed.
 * @param virtual_addr Virtual address to read from.
 * @param read_buffer Array to store the read data.
 * @param size Number of bytes to read.
 * @return VMStatus Indicates the success or failure of the read operation.
 */
VMStatus vm_invpage_read( int pid, void* virtual_addr,       void* read_buffer, size_t size);

/**
 * @brief Prints the page assignments of physical frames into a file.
 * 
 * @param file_name The name of the file to be created.
 * @return VMStatus Indicates the success or failure of the file print operation.
 */
VMStatus vm_invpage_phys_mem_print(const char* file_name);

/**
 * @brief Cleans up the virtual memory manager (VMM) and releases any allocated resources.
 * 
 * @return VMStatus Indicates the success or failure of the cleanup process.
 */
VMStatus vm_invpage_cleanup();
