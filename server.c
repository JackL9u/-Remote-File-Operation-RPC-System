#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include <dirent.h>
#include "TCP_struct.h"
#include "../include/dirtree.h"

#define MAXMSGLEN 100

int sessfd = -1;

// this function is used to debug
// it prints out the memory in hex
void print_bytes(void *ptr, int size) 
{
    unsigned char *p = ptr;
    int i;
    for (i=0; i<size; i++) {
        printf("%02hhX ", p[i]);
    }
    printf("\n");
}

void server_open(open_wrapper* header) {
    fprintf(stderr, "server_open is called\n");
    
    // set the parameters to be called
    int flags = header->flags;
    mode_t mode = header->mode;
    size_t len = header->pathlen;
    char path[len];
    memcpy(path, header->pathname, header->pathlen);
    path[len-1] = 0;

    // check the flags and stuff
    int fd = -1;
    if (flags & O_CREAT) {
        fd = open(path, flags, mode);
    } else {
        fd = open(path, flags);
    }

    if (fd >= 0) {
        fd += OFFSET;
    }

    //pack everything into a char array and send back to client
    char result[2*sizeof(int)];
    memcpy(result, &fd, sizeof(int));
    memcpy(result + sizeof(int), &errno, sizeof(int));
    fprintf(stderr, "server_open finished running\n");
    send(sessfd, result, 2 * sizeof(int), 0);
}

void server_close(close_wrapper* header) {
    fprintf(stderr, "server_close is called\n");
    int fd = header->fd - OFFSET;
    int sf = close(fd);

    //pack everything into a char array and send back to client
    char result[2*sizeof(int)];
    memcpy(result, &sf, sizeof(int));
    memcpy(result + sizeof(int), &errno, sizeof(int));
    fprintf(stderr, "server_close finished running\n");
    send(sessfd, result, 2 * sizeof(int), 0);
}

void server_write(write_wrapper* header) {
    fprintf(stderr, "server_write is called\n");
    int fd = header->fd - OFFSET;
    ssize_t sz = write(fd, header->buf, header->msglen);

    //pack everything into a char array and send back to client
    char result[sizeof(int) + sizeof(ssize_t)];
    memcpy(result, &sz, sizeof(ssize_t));
    memcpy((char*)result + sizeof(ssize_t), &errno, sizeof(int));
    fprintf(stderr, "server_write finished running\n");
    send(sessfd, result, sizeof(int) + sizeof(ssize_t), 0);
}

void server_read(read_wrapper* header) {
    fprintf(stderr, "server_read is called\n");

    size_t readlen = header->readlen;
    int fd = header->fd - OFFSET;

    char msgtoClient[sizeof(ssize_t) + sizeof(int) + readlen];
    void* readbuf = (void*)(msgtoClient + sizeof(ssize_t) + sizeof(int));

    //read the concent into the buf to be sent back to the client
    ssize_t readsz = read(fd, readbuf, readlen);

    //pack everything into a char array and send back to client
    memcpy(msgtoClient, &readsz, sizeof(ssize_t));
    memcpy(msgtoClient + sizeof(ssize_t), &errno, sizeof(int));
    fprintf(stderr, "server_read finished running\n");
    send(sessfd, msgtoClient, sizeof(ssize_t) + sizeof(int) + readsz, 0);
}

void server_lseek(lseek_wrapper* header) {
    fprintf(stderr, "server_lseek is called\n");

    off_t offset = header->offset;
    int fd = header->fd - OFFSET;
    int whence = header->whence;

    off_t rtn = lseek(fd, offset, whence);

    //pack everything into a char array and send back to client
    char result[sizeof(off_t) + sizeof(int)];
    memcpy(result, &rtn, sizeof(off_t));
    memcpy((char*)result + sizeof(off_t), &errno, sizeof(int));
    fprintf(stderr, "server_lseek finished running\n");
    send(sessfd, result, sizeof(off_t) + sizeof(int), 0);
}

void server_stat(stat_wrapper* header) {
    fprintf(stderr, "server_stat is called\n");

    size_t pathlen = header->pathlen;
    //cast the pointer to char pointer to do pointer arithmetic
    char* temp = (char*)header;
    struct stat* statbuf = (struct stat*)(temp + sizeof(size_t));
    char pathname[pathlen];
    memcpy(pathname, header->pathname, pathlen);
    pathname[pathlen-1] = 0;

    int rtn = stat(pathname, statbuf);

    //pack everything into a char array and send back to client
    char result[2*sizeof(int)];
    memcpy(result, &rtn, sizeof(int));
    memcpy(result + sizeof(int), &errno, sizeof(int));
    fprintf(stderr, "server_stat finished running\n");
    send(sessfd, result, 2 * sizeof(int), 0);
}

void server_unlink(unlink_wrapper* header) {
    fprintf(stderr, "server_unlink is called\n");

    size_t pathlen = header->pathlen;
    char pathname[pathlen];
    memcpy(pathname, header->pathname, pathlen);
    pathname[pathlen-1] = 0;

    int rtn = unlink(pathname);

    //pack everything into a char array and send back to client
    char result[2*sizeof(int)];
    memcpy(result, &rtn, sizeof(int));
    memcpy(result + sizeof(int), &errno, sizeof(int));
    fprintf(stderr, "server_unlink finished running\n");
    send(sessfd, result, 2 * sizeof(int), 0);
}

void server_getdirentries(getdirentries_wrapper* header) {
    fprintf(stderr, "server_getdirentries is called\n");

    size_t nbytes = header->nbytes;
    //cast the pointer to char pointer to do pointer arithmetic
    char* temp = (char*)header;
    off_t* basep = (off_t*)(temp + sizeof(size_t));
    int fd = header->fd - OFFSET;

    //pack everything into a char array and send back to client
    char result[sizeof(ssize_t) + sizeof(int) + sizeof(off_t) + nbytes];

    //write n bytes into the buf to be sent back to the client
    ssize_t rtn = getdirentries(fd, result+sizeof(ssize_t)+sizeof(int)+sizeof(off_t), nbytes, basep);
    memcpy(result, &rtn, sizeof(ssize_t));
    memcpy(result + sizeof(ssize_t), &errno, sizeof(int));
    memcpy(result + sizeof(ssize_t) + sizeof(int), basep, sizeof(off_t));
    fprintf(stderr, "server_getdirentries finished running\n");
    send(sessfd, result, sizeof(ssize_t) + sizeof(int) + sizeof(off_t) + nbytes, 0);
}

//total number of bytes needed to write the tree into a buf
size_t getTreeLen(struct dirtreenode* root) {
    size_t namelen = strlen(root->name) + 1;
    size_t totalLen = namelen + sizeof(size_t) + sizeof(int);

    // use recursion
    for (int i = 0; i<root->num_subdirs; i++) {
        totalLen += getTreeLen(root->subdirs[i]);
    }
    return totalLen;
}


// create a char array representation of node, and write
// the infomation into buf
size_t treeToChar(struct dirtreenode* node, char* buf) {
    size_t pathlen = strlen(node->name) + 1;
    size_t sizeTSize = sizeof(size_t);
    size_t intSize = sizeof(int);
    //the total number of bytes needed to write the current node
    size_t totalSize = pathlen + sizeTSize + intSize;

    //values to be written
    size_t pathlenField = pathlen;
    int numSubdirField = node->num_subdirs;
    char* pathnameField = node->name;

    //copy info into the buffer
    memcpy(buf, &pathlenField, sizeof(size_t));
    memcpy(buf+sizeof(size_t), &numSubdirField, sizeof(int));
    memcpy(buf+sizeof(size_t)+sizeof(int), pathnameField, pathlen);

    for (int i = 0; i<node->num_subdirs; i++) {
        size_t subtreeSize = treeToChar(node->subdirs[i], buf+totalSize);
        totalSize += subtreeSize;
    }

    return totalSize;
}

void server_getdirtree(getdirtree_wrapper* header) {
    fprintf(stderr, "server_getdirtree is called\n");

    size_t pathlen = header->pathlen;
    char pathname[pathlen];

    memcpy(pathname, header->pathname, pathlen);
    pathname[pathlen-1] = 0;

    struct dirtreenode* root = getdirtree(pathname);

    size_t treeLen = 0;
    char errmsg[sizeof(size_t) + sizeof(int)];

    // check if pathname is valid, if not, root should be NULL,
    // so we need to stop running the program
    if (root == NULL) {
        memcpy(errmsg, &treeLen, sizeof(size_t));
        memcpy(errmsg + sizeof(size_t), &errno, sizeof(int));
        send(sessfd, errmsg, sizeof(size_t) + sizeof(int), 0);
        fprintf(stderr, "server_getdirtree finished running on error\n");
        return;
    }

    treeLen = getTreeLen(root);
    char treeChar[sizeof(size_t) + sizeof(int) + treeLen];

    //translate the tree into buf
    treeToChar(root, treeChar + sizeof(size_t) + sizeof(int));
    
    //write the total number of bytes and error code
    //pack everything and send back to client
    memcpy(treeChar, &treeLen, sizeof(size_t));
    memcpy(treeChar+sizeof(size_t), &errno, sizeof(int));

    fprintf(stderr, "server_getdirtree finished running\n");
    send(sessfd, treeChar, sizeof(size_t) + sizeof(int) + treeLen, 0);
}

int main(int argc, char**argv) {
    fprintf(stderr, "server started\n");
    char buf[MAXMSGLEN+1];
    char *serverport;
    unsigned short port;
    int sockfd, rv;
    struct sockaddr_in srv, cli;
    socklen_t sa_size;


    // Get environment variable indicating the port of the server
    serverport = getenv("serverport15440");
    if (serverport) port = (unsigned short)atoi(serverport);
    else port=15440;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);    // TCP/IP socket
    if (sockfd<0) err(1, 0);            // in case of error
    
    // setup address structure to indicate server port
    memset(&srv, 0, sizeof(srv));            // clear it first
    srv.sin_family = AF_INET;            // IP family
    srv.sin_addr.s_addr = htonl(INADDR_ANY);    // don't care IP address
    srv.sin_port = htons(port);            // server port

    // bind to our port
    rv = bind(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
    if (rv<0) err(1,0);
    
    // start listening for connections
    rv = listen(sockfd, 5);
    if (rv<0) err(1,0);

    while (1) {
        // wait for next client, get session socket
        sa_size = sizeof(struct sockaddr_in);
        sessfd = accept(sockfd, (struct sockaddr *)&cli, &sa_size);
        if (sessfd<0) err(1,0);
        
        int forkrv;
        forkrv = fork();
        
        if (forkrv == 0) {
            close(sockfd);
            //first receive sizeof(int) + sizeof(size_t) bytes, there encoded the infomation
            //of which kind of request this is (opcode), and the buffer size
            while ((rv = recv(sessfd, buf, sizeof(int) + sizeof(size_t), 0)) > 0) {
                if (rv<0) err(1,0);
            
                char header_begin[sizeof(header_wrapper)];
                memcpy(header_begin, buf, rv);
                header_wrapper* header = (header_wrapper*)header_begin;
                int op_code = header->opcode;
                size_t argsTotalLen = header->argsTotalLen;
                char temp[sizeof(header_wrapper) + argsTotalLen];
                
                //cast the pointer to header_wrapper pointer
                header_wrapper* everything = (header_wrapper*)temp;
                size_t received = 0;

                everything->argsTotalLen = argsTotalLen;
                everything->opcode = op_code;

                // receive the actual arguments, and write into everything: it has this name because it
                // has header info and the actual parameters
                while (received < argsTotalLen) {
                    rv = recv(sessfd,(everything->args) + received, argsTotalLen-received, 0);
                    if (rv<0) err(1,0);
                    received += rv;
                }   
                
                // case on the opcode and determine which request this is
                switch (op_code) {
                    case OPEN:
                        server_open((open_wrapper*)(everything->args));
                        break;
                    case CLOSE:
                        server_close((close_wrapper*)(everything->args));
                        break;
                    case WRITE:
                        server_write((write_wrapper*)(everything->args));
                        break;
                    case READ:
                        server_read((read_wrapper*)(everything->args));
                        break;
                    case LSEEK:
                        server_lseek((lseek_wrapper*)(everything->args));
                        break;
                    case STAT:
                        server_stat((stat_wrapper*)(everything->args));
                        break;
                    case UNLINK:
                        server_unlink((unlink_wrapper*)(everything->args));
                        break;
                    case GETDIRENTRIES:
                        server_getdirentries((getdirentries_wrapper*)(everything->args));
                        break;
                    case GETDIRTREE:
                        server_getdirtree((getdirtree_wrapper*)(everything->args));
                        break;
                    default:
                        break;
                }
            }
            if (rv<0) err(1,0);
            //close session
            close(sessfd);
            exit(0);
        }
    }
    // close socket
    close(sockfd);
    fprintf(stderr, "server finished running\n");
    return 0;
}