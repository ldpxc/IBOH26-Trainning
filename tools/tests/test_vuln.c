#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

void test_stack_overflow(char *input) {
    char small_buf[32];
    char name[16];

    // 1. gets
    gets(small_buf);

    // 2. strcpy & strcat
    strcpy(small_buf, input);
    strcat(small_buf, " suffix");

    // 3. sprintf
    sprintf(small_buf, "Hello %s", input);

    // 4. scanf unbounded %s
    scanf("%s", small_buf);

    // 5. read larger than buffer
    read(0, name, 64);
}

void test_format_string(char *user_input) {
    // Non-constant format string
    printf(user_input);
    fprintf(stderr, user_input);
}

void test_heap() {
    char *chunk1 = malloc(64);
    char *chunk2 = malloc(64);

    // Missing + 1 null terminator
    char *str_copy = malloc(strlen("secret_token"));

    // Integer overflow in malloc
    int count = 1000000;
    char *arr = malloc(count * sizeof(int));

    // Free without nullification
    free(chunk1);

    // Use after free (UAF)
    chunk1[0] = 'X';

    // Double free
    free(chunk1);

    // Free chunk2 properly
    free(chunk2);
    chunk2 = NULL;
}

void test_integers_and_oob(int idx, int user_len) {
    int buffer[10];
    char data[128];

    // OOB negative index (missing idx >= 0)
    if (idx < 10) {
        buffer[idx] = 42;
    }

    // Signed comparison flaw
    if (user_len < 128) {
        read(0, data, user_len);
    }
}

void test_race_and_injection(char *path, char *cmd) {
    // TOCTOU race condition
    if (access(path, F_OK) == 0) {
        int fd = open(path, O_RDONLY);
        close(fd);
    }

    // Command injection
    system(cmd);

    // Insecure PRNG
    srand(time(NULL));
    int token = rand();
}

int main(int argc, char **argv) {
    if (argc > 1) {
        test_format_string(argv[1]);
        test_stack_overflow(argv[1]);
    }
    test_heap();
    return 0;
}
