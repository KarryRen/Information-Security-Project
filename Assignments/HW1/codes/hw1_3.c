/*
 * @Time    : 2024/12/01 15:28
 * @Author  : Karry Ren
 * @Comment : The question 3.1 for Homework 1.
 *            需要绘制第四行代码运行时栈的结构图, 完全参考 Lecture 4 进行绘制
*/

#include <stdio.h>

int GetAvgScore(int score1, int score2) {
    int avg_score = (score1 + score2) / 2;
    return avg_score;
}

int GetScores(int math_score, int physics_score) {
    int total_score = math_score + physics_score;
    int avg_score = GetAvgScore(math_score, physics_score);
    printf("score: %d: %d", total_score, avg_score);
    return total_score;
}

int main() {
    int score = GetScores(82, 88);
    return 0;
}
