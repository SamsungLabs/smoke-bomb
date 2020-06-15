#include <stdio.h>
#include <stdlib.h>
#include "sb_api.h"

typedef struct pp_tag {
	int i1;
	char dummy[28];
} pp_t;

volatile int var __attribute__((annotate("smokeBomb"))) = 10;
volatile int var_arr[4][6] __attribute__((annotate("smokeBomb"))) = {{0,1,2,3}, {9,10,11,12}, {13,14,15,16}, {17,18,19,20}};
volatile int var_arr2[4] __attribute__((annotate("smokeBomb"))) = {1,2,3,4};
volatile int var2 = 20;
volatile pp_t struct_arr[6] __attribute__((annotate("smokeBomb"))) = {
	[0] = {
		.i1 = 10,
	},
};

void hello(void)
{
	printf("hello\n");
}

void hello2(void)
{
	printf("\n===== hello2 =====\n");
	// start of sensitive area. init() should be inserted before.
	printf("var2 : %d\n", var2 + 20);
	printf("var : %d\n", var + 10);		
	printf("var2 : %d\n", var2 + 10);
	if (var2 == 10) {
		printf("var : %d\n", var + 30);	
		if (var2 == 40) {
			printf("var : %d\n", var + 70);		
		}
	}
	printf("var2 : %d\n", var2 + 70);
	// end of sensitive area. exit() should be inserted after.
	// ==> If start & end are located in different basic block, Set sensitive area as maximum size for safety. */
}

void hello3(void)
{
	register int val1, val2, val3;
	printf("\n===== hello3 =====\n");

	val1 = var2 + 20;
	val2 = var + 10;
	val3 = var + 20;

	//printf("var2 : %d\n", val1);
	//printf("var : %d\n", val2);		// start
	//printf("var : %d\n", val3);		// end
	// ==> start & end are located in same basic block. Set sensitive area as minimal size. */
}

void hello_arr(void)
{
	volatile int i1 = 1;
	volatile int i2 = 1;

	printf("\n===== hello_arr =====\n");
	if (var_arr[i1][i2] == 3) {
		printf("var_arr : %d\n", var_arr[i1+1][i2+1]);
	}
	else {
		printf("var_arr : %d\n", var_arr[i1+2][i2+2]);
	}
	printf("var_arr : %lx\n", (unsigned long)var_arr);
}

void hello_struct_arr(int a)
{
	printf("\n===== hell_struct_arr =====\n");
	printf("struct_arr : %d\n", struct_arr[a].i1);
}

void hello_arr2(int a)
{
	volatile int val;
	printf("\n===== hello_arr2 =====\n");

	val = var_arr2[(a >> 1) & 0xff];
}

int main(int argc, char **argv)
{
	int idx;

	//hello2();
	//hello3();
	//hello_arr();

	idx = atoi(argv[1]);

	hello_arr2(idx);
	hello_struct_arr(idx);
	return 0;
}
