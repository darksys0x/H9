#include <stdio.h>
#include <Windows.h>
//1. read the file from disk to heap memory (done);
//2. print the data from heap memory
int fileSize = 0;
void* heapFile = NULL;

int main() {
	FILE* hamadfile = fopen("C:\\Users\\DFIR\\Desktop\\H9_rewritng\\memoryRules.yml", "rb");
	if (hamadfile) {
		fseek(hamadfile, 0, SEEK_END);
		fileSize = ftell(hamadfile);
		fseek(hamadfile, 0, SEEK_SET);
		heapFile = malloc(fileSize);
		fread(heapFile, fileSize, 1, hamadfile);
		fclose(hamadfile);
		printf(" the success to read the file \n");
	}
	else {
		printf("failed to open file\n");
	}
	
	getchar();
	return 0;
}
