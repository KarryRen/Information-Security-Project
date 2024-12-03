/*
 * @Time    : 2024/12/01 14:53
 * @Author  : Karry Ren
 * @Comment : The question 1.1 for Homework 1.
 *            Bug: 如果不加改正, 整体的逻辑是无法实现最终目标的
*/

#include <ctype.h>
#include <string.h>
#include <stdio.h>

void reveal_secret() {
    fputs("SUPER SECRET =42\n", stdout);
}

int verify(const char *name) {
    int i;
    char user[256];
    // 漏洞: 可能会发生数组越界访问
    // 原因: 下面的循环中, 程序尝试访问数组的索引时，索引 10 超出了数组的实际大小 10
    // 可能产生的问题:
    // - 数据损坏：可能无意中修改了不应该修改的内存区域中的数据, 造成数据错误;
    // - 程序崩溃：操作系统可能会检测到内存访问违规并终止程序, 造成程序提前终止出现问题;
    // - 安全漏洞：攻击者可能会利用访问越界来执行任意代码或读取敏感信息, 完成黑客攻击。
    for (i = 0; name[i] != '\0'; ++i) {
        // 这个地方应该用 `/n` 来进行判断逻辑更好
        user[i] = tolower(name[i]);
    }
    user[i] = '\0';
    // 漏洞: 明文显示密码, 很容易被窃取
    return strcmp(user, "xyzzy") == 0;
}

int main() {
    char login[512];
    // 此处的 stdin 表示从标准流读入字符串, 也就是在 terminal 处用键盘输入的
    // fgets 会多读一个换行, 影响了数据的准确性, 一般需要将其给去掉
    fgets(login, 512, stdin);
    login[strcspn(login, "\n")] = '\0';
    if (!verify(login)) {
        return 1;
    }
    reveal_secret();
    return 0;
}
