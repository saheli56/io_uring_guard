#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <liburing.h>
#include <fcntl.h>
#include <unistd.h>

#define NUM_THREADS 50
#define ITERATIONS 1000

void *attack_thread(void *arg) {
    struct io_uring ring;
    if (io_uring_queue_init(64, &ring, 0) < 0) {
        return NULL;
    }

    for (int i = 0; i < ITERATIONS; i++) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
        if (!sqe) continue;

        io_uring_prep_openat(sqe, AT_FDCWD, "/etc/shadow", O_RDONLY, 0);

        io_uring_submit(&ring);

        struct io_uring_cqe *cqe;
        io_uring_wait_cqe(&ring, &cqe);
        
        if (cqe->res >= 0) {
            close(cqe->res);
        }
        io_uring_cqe_seen(&ring, cqe);
    }
    
    io_uring_queue_exit(&ring);
    return NULL;
}

int main() {
    printf("====================================================\n");
    printf("☣️  IORing Guard: Multi-Threaded Stress Tester ☣️\n");
    printf("====================================================\n\n");
    
    printf("[*] Spawning %d concurrent attack threads...\n", NUM_THREADS);
    printf("[*] Each thread will execute %d malicious io_uring operations.\n", ITERATIONS);
    printf("[*] Total Malicious Payload: %d operations.\n\n", NUM_THREADS * ITERATIONS);
    
    printf("[!] IMPORTANT DEMO INSTRUCTIONS:\n");
    printf("    1. If EDR is in ACTIVE mode: This process will be assassinated in 1 millisecond.\n");
    printf("    2. If EDR is in PASSIVE mode: Watch the Dashboard IOPS Graph explode while maintaining 60FPS!\n\n");
    
    printf("Launching attack in 3 seconds...\n");
    sleep(3);
    
    pthread_t threads[NUM_THREADS];
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, attack_thread, NULL);
    }
    
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("[+] Attack complete. If you are reading this, you are in PASSIVE mode!\n");
    return 0;
}
