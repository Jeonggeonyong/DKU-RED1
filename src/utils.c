#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "utils.h"

void print_ransom_note(void) {
    printf("          .                                                      .\n");
    printf("        .n                   .                 .                  n.\n");
    printf("  .   .dP                  dP                   9b                 9b.    .\n");
    printf(" 4    qXb         .       dX                     Xb      .        dXp     t\n");
    printf("dX.    9Xb      .dXb    __                       __     dXb.     dXP     .Xb\n");
    printf("9XXb._       _.dXXXXb dXXXXbo.               .odXXXXb dXXXXb._       _.dXXP\n");
    printf(" 9XXXXXXXXXXXXXXXXXXXVXXXXXXXXOo.           .oOXXXXXXXXVXXXXXXXXXXXXXXXXXXXP\n");
    printf("  `9XXXXXXXXXXXXXXXXXXXXX'~   ~`OOO8b   d8OOO'~   ~`XXXXXXXXXXXXXXXXXXXXXP'\n");
    printf("    `9XXXXXXXXXXXP' `9XX'          `98v8P'          `XXP' `9XXXXXXXXXXXP'\n");
    printf("        ~~~~~~~       9X.          .db|db.          .XP       ~~~~~~~\n");
    printf("                        )b.  .dbo.dP'`v'`9b.odb.  .dX(\n");
    printf("                      ,dXXXXXXXXXXXb     dXXXXXXXXXXXb.\n");
    printf("                     dXXXXXXXXXXXP'   .   `9XXXXXXXXXXXb\n");
    printf("                    dXXXXXXXXXXXXb   d|b   dXXXXXXXXXXXXb\n");
    printf("                    9XXb'   `XXXXXb.dX|Xb.dXXXXX'   `dXXP\n");
    printf("                     `'      9XXXXXX(   )XXXXXXP      `'\n");
    printf("                              XXXX X.`v'.X XXXX\n");
    printf("                              XP^X'`b   d'`X^XX\n");
    printf("                              X. 9  `   '  P )X\n");
    printf("                              `b  `       '  d'\n");
    printf("\n"); 
    printf("                      [ SYSTEM WATCHED, FILES SNATCHED ]\n");
    printf("\n");
}


void print_pikachu_bar(int current, int total) {
    double progress = (double)current / total;
    int pos = BAR_WIDTH * progress;

    // 피카츄 달리는 모션 (짝수/홀수에 따라 모양 변경)
    // 달리는 느낌을 위해 팔/다리 모양을 바꿈
    char *pikachu = (current % 2 == 0) ? "( >'ω')>" : "( ^'ω')^";

    printf("\r  "); // 줄 처음으로

    // 채워진 부분 (번개 모양 + 노란색)
    printf("%s", YELLOW);
    for (int i = 0; i < BAR_WIDTH; i++) {
        if (i < pos) {
            printf("⚡"); 
        } else if (i == pos) {
            // 현재 위치에 피카츄 출력
            printf("%s%s", RESET, pikachu);
        } else {
            // 프로세스바 빈 공간
            printf("  ");
        }
    }

    // 퍼센트 및 색상 복귀
    printf("%s %3d%%", RESET, (int)(progress * 100));
    fflush(stdout);
}