/*
 * fixtures/vulnerable_binary/vuln.c
 *
 * A deliberately tiny, deliberately vulnerable C program, used ONLY to
 * verify the binary agent against something real. Two planted weaknesses:
 *   - a hardcoded AWS-shaped secret
 *   - a call to strcpy() with no bounds checking
 *
 * The "key" below is fake and only exists for this test — never a real
 * credential. Never deploy or ship this binary anywhere.
 *
 * Build:  gcc -o vuln vuln.c
 */
#include <stdio.h>
#include <string.h>

char *API_KEY = "AKIAFAKEEXAMPLE12345";

void copy_input(char *input) {
    char buf[16];
    strcpy(buf, input);
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        copy_input(argv[1]);
    }
    printf("done\n");
    return 0;
}
