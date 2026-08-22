#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <liburing.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define QUEUE_DEPTH 64

void simulate_exfil(struct io_uring *ring) {
    printf("[*] Simulating Data Exfiltration (Reading /etc/shadow)...\n");
    int fd = open("/etc/shadow", O_RDONLY);
    if (fd < 0) {
        printf("    (Note: run as root to actually open the file. Simulating anyway)\n");
    }
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    char buf[128];
    struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
    io_uring_prep_readv(sqe, fd, &iov, 1, 0);
    io_uring_submit(ring);
    printf("[+] Exfiltration payload sent.\n");
}

void simulate_c2(struct io_uring *ring) {
    printf("[*] Simulating Malware C2 (Blind CONNECT flood)...\n");
    for(int i=0; i<3; i++) {
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(1337);
        inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);
        
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        io_uring_prep_connect(sqe, sockfd, (struct sockaddr*)&addr, sizeof(addr));
    }
    io_uring_submit(ring);
    printf("[+] C2 Connect payloads sent.\n");
}

void simulate_lpe(struct io_uring *ring) {
    printf("[*] Simulating LPE (DirtyPipe/UAF via SPLICE & TIMEOUT_REMOVE)...\n");
    struct io_uring_sqe *sqe1 = io_uring_get_sqe(ring);
    io_uring_prep_splice(sqe1, 0, -1, 1, -1, 1024, 0); // Fake splice
    
    struct io_uring_sqe *sqe2 = io_uring_get_sqe(ring);
    io_uring_prep_timeout_remove(sqe2, 1234, 0); // Fake timeout remove
    
    io_uring_submit(ring);
    printf("[+] LPE payloads sent.\n");
}

void simulate_dos(struct io_uring *ring) {
    printf("[*] Simulating Denial of Service (Queue Flooding)...\n");
    for(int i=0; i<500; i++) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        if (sqe) {
            io_uring_prep_nop(sqe);
        } else {
            io_uring_submit(ring);
            sqe = io_uring_get_sqe(ring);
            io_uring_prep_nop(sqe);
        }
    }
    io_uring_submit(ring);
    printf("[+] DoS flood completed.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s [exfil|c2|lpe|dos|all]\n", argv[0]);
        return 1;
    }

    struct io_uring ring;
    io_uring_queue_init(QUEUE_DEPTH, &ring, 0);

    if (strcmp(argv[1], "exfil") == 0) simulate_exfil(&ring);
    else if (strcmp(argv[1], "c2") == 0) simulate_c2(&ring);
    else if (strcmp(argv[1], "lpe") == 0) simulate_lpe(&ring);
    else if (strcmp(argv[1], "dos") == 0) simulate_dos(&ring);
    else if (strcmp(argv[1], "all") == 0) {
        simulate_exfil(&ring);
        sleep(1);
        simulate_c2(&ring);
        sleep(1);
        simulate_lpe(&ring);
        sleep(1);
        simulate_dos(&ring);
    } else {
        printf("Unknown option.\n");
    }

    io_uring_queue_exit(&ring);
    return 0;
}
