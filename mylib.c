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

char *serverip;
char *serverport;
unsigned short port;
char buf[MAXMSGLEN+1];
int sockfd, rv;
struct sockaddr_in srv;

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

// set up the pointers to the original functions
int (*orig_open)(const char *pathname, int flags, ...);  // mode_t mode is needed when flags includes O_CREAT
int (*orig_close)(int fd);
ssize_t (*orig_read)(int fd, void *buf, size_t count);
ssize_t (*orig_write)(int fd, const void *buf, size_t count);
off_t (*orig_lseek)(int fd, off_t offset, int whence);
int (*orig_stat)(const char *pathname, struct stat *statbuf);
int (*orig_unlink)(const char *pathname);
ssize_t (*orig_getdirentries)(int fd, char *restrict buf, size_t nbytes, off_t *restrict basep);
struct dirtreenode* (*orig_getdirtree)(const char *path);
void (*orig_freedirtree)(struct dirtreenode* dt);

int open_helper(const char *pathname, int flags, mode_t m) {
    fprintf(stderr, "mylib: open_helper is called\n");
    
    //pack the parameters
    size_t pathLen = strlen(pathname) + 1; //including the null terminator
    size_t argsTotalLen = sizeof(open_wrapper) + pathLen; //totalLen of the open_wrapper structure
    open_wrapper* args = (open_wrapper*)(malloc(argsTotalLen));
    args->flags = flags;
    args->mode = m;
    args->pathlen = pathLen;
    memcpy(args->pathname, pathname, pathLen);

    //pack the header
    char* header_begin = (char*)(malloc(sizeof(int) + sizeof(size_t) + argsTotalLen));
    header_wrapper* header = (header_wrapper*)header_begin;
    header->opcode = OPEN;
    header->argsTotalLen = argsTotalLen;
    memcpy(header->args, args, argsTotalLen);

    //send the header to server
    send(sockfd, header, sizeof(int) + sizeof(size_t) + argsTotalLen, 0);

    //create a buffer to receive the information
    void* result_receive = malloc(2 * sizeof(int));
    rv = recv(sockfd, result_receive, 2*sizeof(int), 0);
    // if there's something wrong with the connection, dump the program.
    if (rv<0) {
        free(args);
        free(header_begin);
        free(result_receive);
        err(1,0);
    } 

    // map the information out of the received buffer
    int fd = *((int*)result_receive);
    int err = *(int*)(result_receive + sizeof(int));

    if (fd < 0 || err != 0) {
        errno = err;
    }

    free(args);
    free(header_begin);
    free(result_receive);

    fprintf(stderr, "open_helper finished running\n");
    return fd;
}

// This is our replacement for the open function from libc.
int open(const char *pathname, int flags, ...) {
    mode_t m=0;
    if (flags & O_CREAT) {
        va_list a;
        va_start(a, flags);
        m = va_arg(a, mode_t);
        va_end(a);
    }
    int fd = open_helper(pathname, flags, m);
    return fd;
}

int close_helper(int fd) {
    fprintf(stderr, "mylib: close_helper is called\n");
    //want to know if fd is a local file of remote file
    if (fd < OFFSET) {return orig_close(fd);}
    
    //pack the parameters
    size_t argsTotalLen = sizeof(close_wrapper);
    close_wrapper* args = (close_wrapper*)malloc(argsTotalLen);
    args->fd = fd;

    //pack the header
    char* header_begin = (char*)(malloc(sizeof(int) + sizeof(size_t) + argsTotalLen));
    header_wrapper* header = (header_wrapper*)header_begin;
    header->opcode = CLOSE;
    header->argsTotalLen = argsTotalLen;
    memcpy(header->args, args, argsTotalLen);

    //send the header to server
    send(sockfd, header, sizeof(int) + sizeof(size_t) + argsTotalLen, 0);

    //create a buffer to receive the information
    void *result_receive = malloc(2 * sizeof(int));
    rv = recv(sockfd, result_receive, 2*sizeof(int), 0);
    // if there's something wrong with the connection, dump the program.
    if (rv<0) {
        free(args);
        free(header_begin);
        free(result_receive);
        err(1,0);
    }

    // map the information out of the received buffer
    int return_fd = *((int*)result_receive);
    int err = *(int*)(result_receive + sizeof(int));

    if (return_fd < 0 || err != 0) {
        errno = err;
    }

    free(args);
    free(header_begin);
    free(result_receive);

    fprintf(stderr, "close_helper finished running\n");
    return return_fd;
}

int close(int fd) {
    int rtn = close_helper(fd);
    return rtn;
}

ssize_t write_helper(int fd, const void *buf, size_t count) {
    fprintf(stderr, "mylib: write_helper is called\n");
    //want to know if fd is a local file of remote file
    if (fd < OFFSET) {return orig_write(fd, buf, count);}

    //pack the parameters
    size_t argsTotalLen = sizeof(write_wrapper) + count;
    write_wrapper* args = (write_wrapper*)malloc(argsTotalLen);
    args->fd = fd;
    args->msglen = count;
    memcpy(args->buf, buf, count);

    //pack the header
    char* header_begin = (char*)(malloc(sizeof(int) + sizeof(size_t) + argsTotalLen));
    header_wrapper* header = (header_wrapper*)header_begin;
    header->opcode = WRITE;
    header->argsTotalLen = argsTotalLen;
    memcpy(header->args, args, argsTotalLen);

    //send the header to server
    send(sockfd, header, sizeof(int) + sizeof(size_t) + argsTotalLen, 0);

    //create a buffer to receive the information
    void *result_receive = malloc(sizeof(ssize_t) + sizeof(int));
    rv = recv(sockfd, result_receive, sizeof(ssize_t) + sizeof(int), 0);
    // if there's something wrong with the connection, dump the program.
    if (rv<0) {
        free(args);
        free(header_begin);
        free(result_receive);
        err(1,0);
    }

    // map the information out of the received buffer
    ssize_t rtn = *((ssize_t*)result_receive);
    int err = *(int*)(result_receive + sizeof(ssize_t));

    if (rtn < 0 || err != 0) {
        errno = err;
    }

    free(args);
    free(header_begin);
    free(result_receive);

    fprintf(stderr, "write_helper finished running\n");
    return rtn;
}

ssize_t write(int fd, const void *buf, size_t count) {
    ssize_t rtn = write_helper(fd, buf, count);
    return rtn;
}

ssize_t read_helper(int fd, void *buf, size_t count) {
    fprintf(stderr, "mylib: read_helper is called\n");
    //want to know if fd is a local file of remote file
    if (fd < OFFSET) {return orig_read(fd, buf, count);}

    //pack the parameters
    size_t argsTotalLen = sizeof(size_t) + sizeof(int);
    read_wrapper* args = (read_wrapper*)malloc(argsTotalLen);
    args->readlen = count;
    args->fd = fd;
    
    //pack the header
    char* header_begin = (char*)(malloc(sizeof(int) + sizeof(size_t) + argsTotalLen));
    header_wrapper* header = (header_wrapper*)header_begin;
    header->argsTotalLen = argsTotalLen;
    header->opcode = READ;
    memcpy(header->args, args, argsTotalLen);

    //send the header to server
    send(sockfd, header, sizeof(int) + sizeof(size_t) + argsTotalLen, 0);

    //create a buffer to receive the information
    void *result_receive = malloc(sizeof(ssize_t) + sizeof(int));
    rv = recv(sockfd, result_receive, sizeof(ssize_t) + sizeof(int), 0);
    // if there's something wrong with the connection, dump the program.
    if (rv<0) {
        free(args);
        free(header_begin);
        free(result_receive);
        err(1,0);
    }

    // map the information out of the received buffer
    ssize_t rtn = *((ssize_t*)result_receive);
    int erro = *(int*)(result_receive + sizeof(ssize_t));

    if (rtn <= 0 || erro != 0) {
		errno = erro;
		free(args);
        free(header);
		free(result_receive);
        fprintf(stderr, "mylib: read_helper finished running on error\n");
		return rtn;
	}

    //use to record how many bytes have been received.
    //continuing receiving until all the bytes are received
    ssize_t received = 0;
    int rvv = 0;
    while ((rvv = recv(sockfd, (char*)buf + received, rtn - received, 0)) > 0) {
        if (rvv<0) err(1,0);
        received += rvv;
        if (received == rtn) {
            break;
        }
        if (received > rtn) {
			fprintf(stderr, "mylib: read_helper finished running on error\n");
            free(args);
            free(header_begin);
            free(result_receive);
			exit(-1);
		}
    }

    free(args);
    free(header_begin);
    free(result_receive);
    
    fprintf(stderr, "mylib: read_helper finished running\n");
    return rtn;
}

ssize_t read(int fd, void *buf, size_t count) {
    ssize_t rtn = read_helper(fd, buf, count);
    return rtn;
}


off_t lseek_helper(int fd, off_t offset, int whence) {
    fprintf(stderr, "mylib: lseek_helper is called\n");

    //pack the parameters
    size_t argsTotalLen = sizeof(lseek_wrapper);
    lseek_wrapper* args = (lseek_wrapper*)malloc(argsTotalLen);
    args->offset = offset;
    args->fd = fd;
    args->whence = whence;

    //pack the header
    char* header_begin = (char*)(malloc(sizeof(int) + sizeof(size_t) + argsTotalLen));
    header_wrapper* header = (header_wrapper*)header_begin;
    header->opcode = LSEEK;
    header->argsTotalLen = argsTotalLen;
    memcpy(header->args, args, argsTotalLen);

    //send the header to server
    send(sockfd, header, sizeof(int) + sizeof(size_t) + argsTotalLen, 0);

    //create a buffer to receive the information
    void *result_receive = malloc(sizeof(off_t) + sizeof(int));
    rv = recv(sockfd, result_receive, sizeof(off_t) + sizeof(int), 0);
    // if there's something wrong with the connection, dump the program.
    if (rv<0) {
        free(args);
        free(header_begin);
        free(result_receive);
        err(1,0);
    }

    // map the information out of the received buffer
    off_t rtn = *((off_t*)result_receive);
    int err = *(int*)(result_receive + sizeof(off_t));
    if (rtn < 0 || err != 0) {
        errno = err;
    }

    free(args);
    free(header_begin);
    free(result_receive);

    fprintf(stderr, "lseek_helper finished running\n");
    return rtn;
}

off_t lseek(int fd, off_t offset, int whence) {
    off_t rtn = lseek_helper(fd, offset, whence);
    return rtn;
}

int stat_helper(const char *pathname, struct stat *statbuf) {
    fprintf(stderr, "mylib: stat_helper is called\n");

    //pack the parameters
    size_t pathLen = strlen(pathname) + 1; //including the null terminator
    size_t argsTotalLen = sizeof(stat_wrapper) + pathLen;
    stat_wrapper* args = (stat_wrapper*)malloc(argsTotalLen);
    args->pathlen = pathLen;
    args->statbuf = *statbuf;
    memcpy(args->pathname, pathname, pathLen);

    //pack the header
    char* header_begin = (char*)(malloc(sizeof(int) + sizeof(size_t) + argsTotalLen));
    header_wrapper* header = (header_wrapper*)header_begin;
    header->opcode = STAT;
    header->argsTotalLen = argsTotalLen;
    memcpy(header->args, args, argsTotalLen);

    //send the header to server
    send(sockfd, header, sizeof(int) + sizeof(size_t) + argsTotalLen, 0);

    //create a buffer to receive the information
    void* result_receive = malloc(2 * sizeof(int));
    rv = recv(sockfd, result_receive, 2*sizeof(int), 0);
    // if there's something wrong with the connection, dump the program.
    if (rv<0) {
        free(args);
        free(header_begin);
        free(result_receive);
        err(1,0);
    }

    // map the information out of the received buffer
    int rtn = *((int*)result_receive);
    int err = *(int*)(result_receive + sizeof(int));

    if (rtn < 0 || err != 0) {
        errno = err;
    }

    free(args);
    free(header_begin);
    free(result_receive);

    fprintf(stderr, "mylib: stat_helper finished running");
    return rtn;
}

int stat(const char *pathname, struct stat *statbuf) {
    int rtn = stat_helper(pathname, statbuf);
    return rtn;
}

int unlink_helper(const char *pathname) {
    fprintf(stderr, "mylib: unlink_helper is called\n");

    //pack the parameters
    size_t pathLen = strlen(pathname) + 1; //including the null terminator
    size_t argsTotalLen = sizeof(unlink_wrapper) + pathLen;
    unlink_wrapper* args = (unlink_wrapper*)malloc(argsTotalLen);
    args->pathlen = pathLen;
    memcpy(args->pathname, pathname, pathLen);

    //pack the header
    char* header_begin = (char*)(malloc(sizeof(int) + sizeof(size_t) + argsTotalLen));
    header_wrapper* header = (header_wrapper*)header_begin;
    header->opcode = UNLINK;
    header->argsTotalLen = argsTotalLen;
    memcpy(header->args, args, argsTotalLen);

    //send the header to server
    send(sockfd, header, sizeof(int) + sizeof(size_t) + argsTotalLen, 0);

    //create a buffer to receive the information
    void* result_receive = malloc(2 * sizeof(int));
    rv = recv(sockfd, result_receive, 2*sizeof(int), 0);
    // if there's something wrong with the connection, dump the program.
    if (rv<0) {
        free(args);
        free(header_begin);
        free(result_receive);
        err(1,0);
    }

    // map the information out of the received buffer
    int rtn = *((int*)result_receive);
    int err = *(int*)(result_receive + sizeof(int));

    if (rtn < 0 || err != 0) {
        errno = err;
    }

    free(args);
    free(header_begin);
    free(result_receive);

    fprintf(stderr, "mylib: unlink_helper finished running");
    return rtn;
}

int unlink(const char *pathname) {
    int rtn = unlink_helper(pathname);
    return rtn;
}


ssize_t getdirentries_helper(int fd, char* buf, size_t nbytes, off_t* basep) {
    fprintf(stderr, "mylib: getdirentries_helper is called\n");

    //pack the parameters
    size_t argsTotalLen = sizeof(getdirentries_wrapper);
    getdirentries_wrapper* args = (getdirentries_wrapper*)malloc(argsTotalLen);
    args->nbytes = nbytes;
    args->basep = *basep;
    args->fd = fd;

    //pack the header
    char* header_begin = (char*)(malloc(sizeof(int) + sizeof(size_t) + argsTotalLen));
    header_wrapper* header = (header_wrapper*)header_begin;
    header->opcode = GETDIRENTRIES;
    header->argsTotalLen = argsTotalLen;
    memcpy(header->args, args, argsTotalLen);

    //send the header to server
    send(sockfd, header, sizeof(int) + sizeof(size_t) + argsTotalLen, 0);

    //receive everything in a single revc()
    //rtn, err, basep;
    size_t receive_size = sizeof(ssize_t) + sizeof(int) + sizeof(off_t) + nbytes;
    void *result_receive = malloc(receive_size);
    rv = recv(sockfd, result_receive, receive_size, 0);
    // if there's something wrong with the connection, dump the program.
    if (rv<0) {
        free(args);
        free(header_begin);
        free(result_receive);
        err(1,0);
    }

     // map the information out of the received buffer
    ssize_t rtn = *((ssize_t*)result_receive);
    int err = *(int*)(result_receive + sizeof(ssize_t));
    *basep = *(off_t *)(result_receive + sizeof(ssize_t) + sizeof(int));
    memcpy(buf, result_receive + sizeof(ssize_t) + sizeof(int) + sizeof(off_t), nbytes);

    if (rtn < 0 || err != 0) {
        errno = err;
    }

    free(args);
    free(header_begin);
    free(result_receive);

    fprintf(stderr, "getdirentries_helper finished running\n");
    return rtn;
}

ssize_t getdirentries(int fd, char* buf, size_t nbytes, off_t* basep) {
    ssize_t rtn = getdirentries_helper(fd, buf, nbytes, basep);
    return rtn;
}

// this global variable is used to track how many bytes have been looked at in the buf
// so we can start translate the next dirtreenode from appropriate memory address in the
//char array
size_t writtenSize = 0;

// create the full dirtreenode struct using its corresponding array representation
struct dirtreenode* charToTree(char* buf) {
    struct dirtreenode* root = (struct dirtreenode*)malloc(sizeof(struct dirtreenode));

    // find the starting position of the current dirtreenode in the array
    char* bufstart = buf + writtenSize;

    // map the information out of the char array
    size_t pathlen = *((size_t*)bufstart);
    int num_subdirs = *(int*)(bufstart+sizeof(size_t));
    char* name = (char*)malloc(pathlen);
    memcpy(name, bufstart+sizeof(size_t)+sizeof(int), pathlen);
    
    size_t nodeTotalLen = sizeof(size_t) + sizeof(int) + pathlen;
    writtenSize += nodeTotalLen;

    // set up the parameters
    root->name = name;
    root->num_subdirs = num_subdirs;
    root->subdirs = NULL;

    // set up the third field in the dirtreenode struct
    if (num_subdirs > 0) {
        struct dirtreenode** subdirs = (struct dirtreenode**)malloc(num_subdirs * sizeof(struct dirtreenode*));
        root->subdirs = subdirs;
    }

    // recursively create all the sub-directories
    for (int i = 0; i<num_subdirs; i++) {
        root->subdirs[i] = charToTree(buf);
    }

    // return the struct created
    return root;
}

struct dirtreenode* getdirtree_helper(const char *pathname) {
    fprintf(stderr, "mylib: getdirtree_helper is called\n");

    //pack the parameters
    size_t pathLen = strlen(pathname) + 1; //including the null terminator
    size_t argsTotalLen = sizeof(size_t) + pathLen;
    getdirtree_wrapper* args = (getdirtree_wrapper*)malloc(argsTotalLen);
    args->pathlen = pathLen; //including the null terminator;
    memcpy(args->pathname, pathname, pathLen);

    //pack the header
    char* header_begin = (char*)(malloc(sizeof(int) + sizeof(size_t) + argsTotalLen));
    header_wrapper* header = (header_wrapper*)header_begin;
    header->opcode = GETDIRTREE;
    header->argsTotalLen = argsTotalLen;
    memcpy(header->args, args, argsTotalLen);

    //send the header to server
    send(sockfd, header, sizeof(int) + sizeof(size_t) + argsTotalLen, 0);

    //create a buffer to receive the information
    void* result_receive = malloc(sizeof(size_t) + sizeof(int));
    rv = recv(sockfd, result_receive, sizeof(size_t) + sizeof(int), 0);
    // if there's something wrong with the connection, dump the program.
    if (rv<0) {
        free(args);
        free(header_begin);
        free(result_receive);
        err(1,0);
    }

    // map the information out of the received buffer
    // first map the returned bytes and err code
    size_t totalBytes = *((size_t*)result_receive);
    int erro = *(int*)(result_receive + sizeof(size_t));
    if (totalBytes == 0 || erro != 0) {
        errno = erro;
        free(args);
        free(header_begin);
        free(result_receive);
        fprintf(stderr, "mylib: getdirtree_helper finished running on error\n");
        return NULL;
    }

    // map out the actual returned value into buf
    size_t received = 0;
    char buf[totalBytes];
    int rvv = 0;
    while ((rvv = recv(sockfd, buf + received, totalBytes-received, 0)) > 0) {
        // check for error
        if (rvv<0) err(1,0);
        received += rvv;
        if (received >= totalBytes) {
            break;
        }
    }

    // create the dirtreenode structure using the char array received
    struct dirtreenode* root = charToTree(buf);

    free(args);
    free(header_begin);
    free(result_receive);

    fprintf(stderr, "mylib: getdirtree_helper finished running\n");
    return root;
}

struct dirtreenode* getdirtree(const char *path) {
    struct dirtreenode* rtn = getdirtree_helper(path);
    return rtn;
}

// didn't modify the dirtreenode struct, so free function doesn't need to change
void freedirtree(struct dirtreenode* dt) {
    fprintf(stderr, "mylib: freedirtree is called\n");
    orig_freedirtree(dt);
    fprintf(stderr, "mylib: freedirtree finished running\n");
    return;
}

// This function is automatically called when program is started
void _init(void) {

    // Get environment variable indicating the ip address of the server
    serverip = getenv("server15440");
    if (serverip) fprintf(stderr, "Got environment variable server15440: %s\n", serverip);
    else {
        fprintf(stderr, "Environment variable server15440 not found.  Using 127.0.0.1\n");
        serverip = "127.0.0.1";
    }
    
    // Get environment variable indicating the port of the server
    serverport = getenv("serverport15440");
    if (serverport) fprintf(stderr, "Got environment variable serverport15440: %s\n", serverport);
    else {
        fprintf(stderr, "Environment variable serverport15440 not found.  Using 15440\n");
        serverport = "15440";
    }
    port = (unsigned short)atoi(serverport);
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);    // TCP/IP socket
    if (sockfd<0) err(1, 0);            // in case of error
    
    // setup address structure to point to server
    memset(&srv, 0, sizeof(srv));            // clear it first
    srv.sin_family = AF_INET;            // IP family
    srv.sin_addr.s_addr = inet_addr(serverip);    // IP address of server
    srv.sin_port = htons(port);            // server port

    // actually connect to the server
    rv = connect(sockfd, (struct sockaddr*)&srv, sizeof(struct sockaddr));
    if (rv<0) err(1,0);

    // set function pointer orig_open to point to the original open function
    orig_open = dlsym(RTLD_NEXT, "open");
    orig_close = dlsym(RTLD_NEXT, "close");
    orig_read = dlsym(RTLD_NEXT, "read");
    orig_write = dlsym(RTLD_NEXT, "write");
    orig_lseek = dlsym(RTLD_NEXT, "lseek");
    orig_stat = dlsym(RTLD_NEXT, "stat");
    orig_unlink = dlsym(RTLD_NEXT, "unlink");
    orig_getdirentries = dlsym(RTLD_NEXT, "getdirentries");
    orig_getdirtree = dlsym(RTLD_NEXT, "getdirtree");
    orig_freedirtree = dlsym(RTLD_NEXT, "freedirtree");
}