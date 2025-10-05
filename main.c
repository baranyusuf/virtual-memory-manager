#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vmpagelib.h"
#include "vminvpagelib.h"


// This is an example program that demonstrates the use of a virtual memory manager (VMM) to allocate and manage memory for a process.
// This file is for your reference only. We will test your implementation using our own main.c file and test cases.

int main(int argc, char** argv){
    // Initialize the virtual memory manager
    VMStatus status = vm_page_init();
    if (status != VM_OK) {
        fprintf(stderr, "Failed to initialize virtual memory manager\n");
        return EXIT_FAILURE;
    }

    // Create a new process with PID 1
    status = vm_page_create_process(1);
    if (status != VM_OK) {
        fprintf(stderr, "Failed to create process\n");
        return EXIT_FAILURE;
    }

    // Allocate 6048 bytes of memory for the process
    void* virtual_addr;
    status = vm_page_alloc(1, 6048, &virtual_addr);
    if (status != VM_OK) {
        fprintf(stderr, "Failed to allocate memory\n");
        return EXIT_FAILURE;
    }

    // Translate the virtual address to a physical address
    void* physical_addr;
    status = vm_page_translate(1, virtual_addr, &physical_addr);
    if (status != VM_OK) {
        fprintf(stderr, "Failed to translate address\n");
        return EXIT_FAILURE;
    }

    printf("Virtual address: %p\n", virtual_addr);
    printf("Physical address: %p\n", physical_addr);
    
    // Write data to the allocated memory
    char write_data[6048];
    memset(write_data, 'A', sizeof(write_data));
    status = vm_page_write(1, virtual_addr, write_data, sizeof(write_data));
    if (status != VM_OK) {
        fprintf(stderr, "Failed to write data\n");
        return EXIT_FAILURE;
    }
    
    // Read data from the allocated memory
    char read_buffer[6048];
    status = vm_page_read(1, virtual_addr, read_buffer, sizeof(read_buffer));
    if (status != VM_OK) {
        fprintf(stderr, "Failed to read data\n");
        return EXIT_FAILURE;
    }
    
    // Verify the read data
    if (memcmp(write_data, read_buffer, sizeof(write_data)) != 0) {
        fprintf(stderr, "Data mismatch\n");
        return EXIT_FAILURE;
    }
    printf("Data read successfully\n");

    // Free the allocated memory
    status = vm_page_free(1, virtual_addr);
    if (status != VM_OK) {
        fprintf(stderr, "Failed to free memory\n");
        return EXIT_FAILURE;
    }

    // Clean up the virtual memory manager
    status = vm_page_cleanup();
    if (status != VM_OK) {
        fprintf(stderr, "Failed to clean up virtual memory manager\n");
        return EXIT_FAILURE;
    }

    // Initialize the inverted page table
    status = vm_invpage_init();
    if (status != VM_OK) {
        fprintf(stderr, "Failed to initialize inverted page table\n");
        return EXIT_FAILURE;
    }
    
    // Create a new process with PID 2
    status = vm_invpage_create_process(2);
    if (status != VM_OK) {
        fprintf(stderr, "Failed to create process\n");
        return EXIT_FAILURE;
    }
    
    // Allocate 6048 bytes of memory for the process
    void* inv_virtual_addr;
    status = vm_invpage_alloc(2, 6048, &inv_virtual_addr);
    if (status != VM_OK) {
        fprintf(stderr, "Failed to allocate memory\n");
        return EXIT_FAILURE;
    }
    
    // Translate the virtual address to a physical address
    void* inv_physical_addr;
    status = vm_invpage_translate(2, inv_virtual_addr, &inv_physical_addr);
    if (status != VM_OK) {
        fprintf(stderr, "Failed to translate address\n");
        return EXIT_FAILURE;
    }
    printf("Inverted Virtual address: %p\n", inv_virtual_addr);
    printf("Inverted Physical address: %p\n", inv_physical_addr);
    
    // Write data to the allocated memory
    char inv_write_data[6048];
    memset(inv_write_data, 'B', sizeof(inv_write_data));
    status = vm_invpage_write(2, inv_virtual_addr, inv_write_data, sizeof(inv_write_data));
    if (status != VM_OK) {
        fprintf(stderr, "Failed to write data\n");
        return EXIT_FAILURE;
    }
    
    // Read data from the allocated memory
    char inv_read_buffer[6048];
    status = vm_invpage_read(2, inv_virtual_addr, inv_read_buffer, sizeof(inv_read_buffer));
    if (status != VM_OK) {
        fprintf(stderr, "Failed to read data\n");
        return EXIT_FAILURE;
    }
    
    // Verify the read data
    if (memcmp(inv_write_data, inv_read_buffer, sizeof(inv_write_data)) != 0) {
        fprintf(stderr, "Data mismatch\n");
        return EXIT_FAILURE;
    }
    printf("Inverted Data read successfully\n");
    
    // Free the allocated memory
    status = vm_invpage_free(2, inv_virtual_addr);
    if (status != VM_OK) {
        fprintf(stderr, "Failed to free memory\n");
        return EXIT_FAILURE;
    }
    
    // Clean up the inverted page table
    status = vm_invpage_cleanup();
    if (status != VM_OK) {
        fprintf(stderr, "Failed to clean up inverted page table\n");
        return EXIT_FAILURE;
    }
    printf("All tests passed successfully\n");

    return EXIT_SUCCESS;
}