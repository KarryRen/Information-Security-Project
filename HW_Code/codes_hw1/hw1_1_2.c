/*
 * @Time    : 2024/12/01 14:43
 * @Author  : Karry Ren
 * @Comment : The question 1.2 for Homework 1.
*/

#include <stdio.h>

void loop() {
    int i = 0;
    int a[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    // 漏洞: 发生了数组越界访问
    // 原因: 下面的循环中, 程序尝试访问数组的索引时，索引 10 超出了数组的实际大小 10
    // 可能产生的问题:
    // - 数据损坏：可能无意中修改了不应该修改的内存区域中的数据, 造成数据错误;
    // - 程序崩溃：操作系统可能会检测到内存访问违规并终止程序, 造成程序提前终止出现问题;
    // - 安全漏洞：攻击者可能会利用访问越界来执行任意代码或读取敏感信息, 完成黑客攻击。
    // - ... 还需补充
    for (i = 0; i < 11; i++) {
        a[i] = 0;
        printf("Hello World\n");
    }
    return;
}

int main() {
    loop();
    printf("Hello C++");
    return 0;
}
