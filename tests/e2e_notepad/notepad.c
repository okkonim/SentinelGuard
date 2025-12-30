// Simple program named notepad.exe that connects to a local server and sends a message
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
    const char *server_ip = "127.0.0.1";
    int server_port = 9001;
    if (argc >= 2) server_port = atoi(argv[1]);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 1;

    struct sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(server_port);
    inet_pton(AF_INET, server_ip, &servaddr.sin_addr);

    if (connect(sock, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
        perror("connect");
        close(sock);
        return 1;
    }

     const char *msg = "hello from notepad.exe\n";
     send(sock, msg, strlen(msg), 0);
     /* Increase the wait time so the connection remains visible to the monitor
         and the test doesn't miss the anomaly due to the connection closing too quickly */
     sleep(8);
    close(sock);
    return 0;
}
