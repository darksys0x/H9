#include<stdio.h>
#include<Windows.h>
//1. get the file size from disk and allocate in memory,


long fileSize = 0;
long currentOffset = 0;
void* heapFileDate = NULL;

char fileLines[50][200];
int totalLines = 0;

void printLineByLineFromHeapMemory( ) {
	char* p = (char*)heapFileDate;
	char line[200];
	int i = 0;
	
	
	DWORD currentIndex = 0;
	for ( ; i < fileSize; i++) {
		line[currentIndex] = p[i];
		if(p[i] == '\n'){

			
			
			line[currentIndex] = '\0';
			currentIndex = 0;

			printf("%s\n", line);
			strncpy(fileLines[totalLines], line, strlen(line)+1);//strlen(line)+1 = that's mean string+nullTremantel
			//sprintf(fileLines[totalLines], "%s", line);
			totalLines++;
			
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



void parseYamlFileLines() {
}

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

	fileLines;
	return 0;
}




