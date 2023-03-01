#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libcrypto.lib")

#define BUF_SIZE 1024
#define AES_KEY_SIZE 128
#define AES_BLOCK_SIZE 16

void error(const char *msg)
{
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main(int argc, char* argv[])
        {
            WSADATA wsa;
            SOCKET sockfd, newsockfd;
            struct sockaddr_in serv_addr, cli_addr;
            int portno;
            char buffer[BUF_SIZE];
            char bufferin[BUF_SIZE];
            int n;

            if (argc != 3)
            {
                error("usage: serv.exe portno aes_key");
            }

            // 初始化Winsock库
            if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            {
                error("WSAStartup failed");
            }

            // 创建套接字
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            if (sockfd == INVALID_SOCKET)
            {
                error("socket creation failed");
            }

            // 设置服务器地址和端口号
            portno = atoi(argv[1]);
            char* aes_key = argv[2];

            memset(&serv_addr, 0, sizeof(serv_addr));
            serv_addr.sin_family = AF_INET;
            serv_addr.sin_addr.s_addr = INADDR_ANY;
            serv_addr.sin_port = htons(portno);

            // 绑定套接字到指定端口号
            if (bind(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR)
            {
                error("socket bind failed");
            }

            // 监听套接字
            if (listen(sockfd, 1) == SOCKET_ERROR)
            {
                error("socket listen failed");
            }

            printf("Server listening on port %d\n", portno);

            // 接受客户端连接
            int clilen = sizeof(cli_addr);
            newsockfd = accept(sockfd, (struct sockaddr*)&cli_addr, &clilen);
            if (newsockfd == INVALID_SOCKET)
            {
                error("socket accept failed");
            }

            printf("Client connected\n");

            // 设置AES加密密钥

            EVP_CIPHER_CTX* enc_ctx, * dec_ctx;
            enc_ctx = EVP_CIPHER_CTX_new();
            dec_ctx = EVP_CIPHER_CTX_new();
            if (enc_ctx == NULL || dec_ctx == NULL)
            {
                error("EVP_CIPHER_CTX_new failed");
            }
            if (EVP_EncryptInit_ex(enc_ctx, EVP_aes_128_cbc(), NULL, (unsigned char*)aes_key, NULL) != 1)
            {
                error("EVP_EncryptInit_ex failed");
            }
            if (EVP_DecryptInit_ex(dec_ctx, EVP_aes_128_cbc(), NULL, (unsigned char*)aes_key, NULL) != 1)
            {
                error("EVP_DecryptInit_ex failed");
            }

            // 循环等待用户输入命令
            while (1)
            {
                printf("> ");

                // 读取用户输入的命令
                memset(bufferin, 0, BUF_SIZE);
                fgets(bufferin, BUF_SIZE - 1, stdin);

                // 如果用户输入"exit"，则退出循环
                if (strncmp(bufferin, "exit", 4) == 0)
                {

                    break;
                }
                


                // 加密并发送命令
                if (strlen(bufferin) > 0) {
                    int outlen = 0;

                    unsigned char* data = reinterpret_cast<unsigned char*>(bufferin);
                    unsigned char encrypted_bufferin[BUF_SIZE]; // 新的加密缓冲区
                    if (EVP_EncryptUpdate(enc_ctx, encrypted_bufferin, &outlen, (unsigned char*)bufferin, strlen(bufferin)) != 1)
                    {
                        error("EVP_EncryptUpdate failed");
                    }
                    int encrypted_length = outlen;
                    if (EVP_EncryptFinal_ex(enc_ctx, encrypted_bufferin + outlen, &outlen) != 1)
                    {
                        error("EVP_EncryptFinal_ex failed");
                    }
                    encrypted_length += outlen;


                    const char* encrypted_data = reinterpret_cast<const char*>(encrypted_bufferin);
                    n = send(newsockfd, encrypted_data, encrypted_length, 0);
                    if (n == SOCKET_ERROR)
                    {
                        error("socket send failed");
                    }

                }

                //接收加密的命令执行结果
                memset(buffer, 0, BUF_SIZE);
                n = recv(newsockfd, buffer, BUF_SIZE, 0);
                if (n <= 0)
                {
                    error("socket recv failed");
                }

                unsigned char decrypted_buffer[BUF_SIZE];
                memset(decrypted_buffer, 0, BUF_SIZE);

                int outlen2 = 0;
                if (EVP_DecryptUpdate(dec_ctx, decrypted_buffer, &outlen2, (unsigned char*)buffer, n) != 1)
                {
                    error("EVP_DecryptUpdate failed");
                }
                int decrypted_length = outlen2;
                if (EVP_DecryptFinal_ex(dec_ctx, decrypted_buffer + outlen2, &outlen2) != 1)
                {
                    error("EVP_DecryptFinal_ex failed");
                }
                decrypted_length += outlen2;

                decrypted_buffer[decrypted_length] = '\0';
                
                printf("%s", bufferin);
                if (strncmp(bufferin, "file", 4) == 0) {


                    // file 命令
                    char* client_file = strtok(bufferin + 5, " ");
                    char* server_file = strtok(NULL, " \n");
                    //if (client_file == NULL || server_file == NULL) {
                        //error("file 命令使用方法：file client_file server_file");
                    //}

                    
                    FILE* fp = fopen(server_file, "wb");
                    if (fp == NULL) {
                        error("打开文件失败");
                    }

                    fwrite(decrypted_buffer, 1, decrypted_length, fp);

                    fclose(fp);

                    printf("文件 %s 已保存到 %s\n", client_file, server_file);
                }
                else
                {
                    printf("%s", decrypted_buffer);
                }

            }

            // 清理加密上下文和套接字
            EVP_CIPHER_CTX_free(enc_ctx);
            EVP_CIPHER_CTX_free(dec_ctx);
            closesocket(newsockfd);
            closesocket(sockfd);
            WSACleanup();
            return 0;
}


