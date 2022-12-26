#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SERV_IP "0.0.0.0"
#define SERV_PORT 9527

const char *req_header = "GET / HTTP/1.1\r\nUser-Agent: curl/7.20.0 (x86_64-target-linux-gnu) libcurl/7.32.0 GnuTLS/2.12.23 zlib/1.2.8\r\nHost: 0.0.0.0\r\nAccept: */*\r\n\r\n";


int main(void)
{
    int sfd, len;
    struct sockaddr_in serv_addr;
    char buf[BUFSIZ];

    sfd = socket(AF_INET, SOCK_STREAM, 0);

    bzero(&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    inet_pton(AF_INET, SERV_IP, &serv_addr.sin_addr.s_addr);
    serv_addr.sin_port = htons(SERV_PORT);

    connect(sfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    /*
    write(sfd, req_header, strlen(req_header));

    while (1)
    {
        len = read(sfd, buf, sizeof(buf));
        if (len > 0) {
            printf("buf: %s\n", buf);
        } else {
            printf("read 0\n");
            break;
        }
    }
    */

    close(sfd);
    return 0;
}
