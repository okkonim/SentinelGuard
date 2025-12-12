// Простая программа, именуемая notepad.exe, которая подключается к локальному серверу и отправляет сообщение
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
     /* Увеличиваем время ожидания, чтобы соединение оставалось видимым для мониторинга
         и тест не пропускал аномалию из-за слишком быстрой разрыва */
     sleep(8);
    close(sock);
    return 0;
}
