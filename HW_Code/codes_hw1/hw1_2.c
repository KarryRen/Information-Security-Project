/*
 * @Time    : 2024/12/01 15:28
 * @Author  : Karry Ren
 * @Comment : The question 2.1 for Homework 1.
 *            使用 gets 函数的漏洞对 true_password 进行注入, 修改其真实值, 只需要算好需要多少位即可
 *            一个可能的方法是 `ABCDEFGHIGKLMN                  ABCDEFGHIGKLMN`
 *                           注意中间的字符为 [NULL] 的输入表达, 不同的 os 可能不同, 你可以先运行下面一段代码看一下
 *                            char a[3] = "55\0";
 *                            for(int i = 0; i <3; i++){
 *                                printf("%c", a[i]);
 *                            }
 *            也就是说 `16 Byte 的字符串 + 16 Byte (4*4) 的空 + 和前面 16 Byte 字符串完全相同的字符串`
 *            需要画图说明原理, 但是仔细思考后应该不难发现这个道理。
*/

#include <stdio.h>
#include <string.h>

void verify() {
    char true_password[16] = "Ft369BfiA";
    int a[4] = {0, 1, 2, 3};
    char inputs[16];
    while (1) {
        printf("Please enter your password:");
        gets(inputs);
        printf("**** inputs[]: %s\n", inputs);
        printf("**** true_password[]: %s\n", true_password);
        if (strcmp(inputs, true_password)) {
            printf("Sorry, your password is wrong!\n");
        } else {
            printf("Welcome!\n");
        }
    }
}

int main() {
    verify();
    return 0;
}
