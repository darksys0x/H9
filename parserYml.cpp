#include<stdio.h>
#include<Windows.h>
//1. get the file size from disk and allocate in memory,


long fileSize = 0;
long currentOffset = 0;
void* heapFileDate = NULL;



void printLineByLineFromHeapMemory( ) {
	char* p = (char*)heapFileDate;
	char line[200];
	int i = 0;
	
	
	DWORD currentIndex = 0;
	for ( ; i < fileSize; i++) {
		line[currentIndex] = p[i];
		if(p[i] == '\n'){

			// we have a complete line now
			
			line[currentIndex] = '\0';
			
			printf("%s\n", line);

			currentIndex = 0;
			
			
		}

		else
		{
			currentIndex++;

		} 
		

	}


	if (fileSize == i) {
		line[currentIndex] = '\0';
		printf("%s\n", line);
	}
	


}






//
//void printLineByLineFromHeapMemory() {
//	char* p = (char*)heapFileDate;
//	char line[200];
//
//	int lineIndex = 0;
//	for (int i = 0; i < fileSize; i++) {
//		//printf("%c", p[i]);
//		if (p[i] == '\n') {
//
//			line[lineIndex] = '\0';
//			printf("%s\n", line);
//			lineIndex = 0;
//		}
//		else {
//			line[lineIndex] = p[i]; // copy from file in heap to line
//			lineIndex++;
//		}
//
//	}
//}


int main() {
	FILE* hamadFile = fopen("C:\\Users\\DFIR\\Desktop\\H9_rewritng\\memoryRules.yml", "rb");
	if (hamadFile) {
		fseek(hamadFile, 0, SEEK_END);
		fileSize = ftell(hamadFile);
		fseek(hamadFile, 0, SEEK_SET);
		heapFileDate = malloc(fileSize);
		fread(heapFileDate, fileSize, 1, hamadFile);
		fclose(hamadFile);

		
		
	}
	else
	{
		printf("failed to read file");

	}
	printLineByLineFromHeapMemory();
	
}




