/*
 * @Time    : 2024/12/01 17:01
 * @Author  : Karry Ren
 * @Comment : The question 1.3 for Homework 1.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static int secret;

int func(char *name) {
    int canary = secret;
    char buffer[12];
    strcpy(buffer, name); // name 过长可能会造成复制出现溢出的情况
    if (canary == secret) {
        printf("equal secret=%d, canary=%d\n", secret, canary);
        return 1;
    } else {
        printf("un equal secret=%d, canary=%d\n", secret, canary);
        exit(1);
    }
}

int main(int argc, char *argv[]) {
    secret = rand(); // getRandomNumber()
    char str[256];
    if (fgets(str, 256, stdin) == NULL) {
        return 0;
    }
    func(str);
    return 0;
}