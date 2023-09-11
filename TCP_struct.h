#include <sys/types.h>

#define OPEN 0
#define CLOSE 1
#define WRITE 2
#define READ 3
#define LSEEK 4
#define STAT 5
#define UNLINK 6
#define GETDIRENTRIES 7
#define GETDIRTREE 8

//set offset relatively large
#define OFFSET 5200

typedef struct header_marshalling{
    size_t argsTotalLen; //argsTotalLen is number of bytes that follows this header. starting in args
    int opcode;
    char args[0];
} header_wrapper;

typedef struct Open_marshalling {
    size_t pathlen;
    int flags;
    mode_t mode;
    char pathname[0];
} open_wrapper;

typedef struct Close_marshalling {
    int fd;
} close_wrapper;

typedef struct Write_marshalling {
    size_t msglen;
    int fd;
    char buf[0];
} write_wrapper;

typedef struct Read_marshalling {
    size_t readlen;
    int fd;
} read_wrapper;

typedef struct Lseek_marshalling {
    off_t offset;
    int fd;
    int whence;
} lseek_wrapper;

typedef struct Stat_marshalling {
    size_t pathlen;
    struct stat statbuf;
    char pathname[0];
} stat_wrapper;

typedef struct Unlink_marshalling {
    size_t pathlen;
    char pathname[0];
} unlink_wrapper;

typedef struct Getdirentries_marshalling {
    size_t nbytes;
    off_t basep;
    int fd;
} getdirentries_wrapper;

typedef struct Getdirtree_marshalling {
    size_t pathlen;
    char pathname[0];
} getdirtree_wrapper;