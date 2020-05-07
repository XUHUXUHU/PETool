#if !defined (METHOD_H)
#define METHOD_H
#include "structOfPE.h"
#include <stdio.h>

bool enableDebugPriv();

char* getFileContent(char* filePath_p,int* fileBufferSize_p){
	FILE *fp;
	if((fp=fopen(filePath_p,"rb"))==NULL){
		char info[] = "failure to open this file!";
		strcat(info,filePath_p);
		MessageBoxA(0,info,0,0);
		return 0;
	}
	fseek(fp,0,SEEK_END);		
    long length=ftell(fp);		//ftell������ļ��ĳ���
	fseek(fp,0,SEEK_SET);
	char* p = (char*)malloc(length);
	if(!p){
		MessageBox(0,TEXT("����ռ�ʧ�ܣ�"),0,0);
		fclose(fp);
		return 0;
	}
	//���ļ���ȡ��������
	int isGetContent = fread(p,length,1,fp);
	if(!isGetContent){
		MessageBox(0,TEXT("��ȡ����ʧ�ܣ�"),0,0);
		fclose(fp);
		return 0;
	}
	if(fileBufferSize_p){
		*fileBufferSize_p = length;
	}
	fclose(fp);
	return p;
}

int pushContentToFile(char* buffer_p,int size,char* filename){
	FILE* fp;
	if((fp=fopen(filename,"wb"))==NULL){
		char info[] = "failure to open this file1!";
		strcat(info,filename);
		MessageBoxA(0,info,0,0);
		return 0;
	}
	fwrite(buffer_p,size,1,fp);
	fclose(fp);
	return 1;
}

char* fileBufferToImageBuffer(char* fileBuffer_p,int* imageBufferSize_p,wholePE* PE){
	wholePE* tempPE = PE;
	char* tempImageBuffer_p = NULL;
	tempImageBuffer_p = (char*)malloc(tempPE->optionPEHeader_p->SizeOfImage);
	if(!tempImageBuffer_p){
		printf("ΪImageBuffer����ռ�ʧ�ܣ�");
		return 0;
	}
	//��ʼ�����䵽���ڴ�
	memset(tempImageBuffer_p,0,tempPE->optionPEHeader_p->SizeOfImage);
	//����SizeOfHeaders��Copyͷ
	memcpy(tempImageBuffer_p,fileBuffer_p,tempPE->optionPEHeader_p->SizeOfHeaders);
	//���ݽڱ�ѭ��copy��
	for(int i=0;i<tempPE->PEHeader_p->NumberOfSections;i++,tempPE->sectionHeader_p++){
		memcpy(tempImageBuffer_p+tempPE->sectionHeader_p->VirtualAddress,fileBuffer_p+tempPE->sectionHeader_p->PointerToRawData,tempPE->sectionHeader_p->SizeOfRawData);
	}
	if(imageBufferSize_p){
		*imageBufferSize_p = PE->optionPEHeader_p->SizeOfImage;
	}
	return	tempImageBuffer_p;
}

char* imageBufferToFileBuffer(char* imageBuffer_p,int* fileBufferSize_p,wholePE* PE){
	wholePE* tempPE = PE;
	char* tempFileBuffer_p = NULL;
	tempFileBuffer_p = (char*)malloc((tempPE->sectionHeader_p+tempPE->PEHeader_p->NumberOfSections-1)->PointerToRawData+(tempPE->sectionHeader_p+tempPE->PEHeader_p->NumberOfSections-1)->SizeOfRawData);
	memcpy(tempFileBuffer_p,imageBuffer_p,tempPE->optionPEHeader_p->SizeOfHeaders);
	for(int i=0;i<tempPE->PEHeader_p->NumberOfSections;i++,tempPE->sectionHeader_p++){
		memcpy(tempFileBuffer_p+tempPE->sectionHeader_p->PointerToRawData,imageBuffer_p+tempPE->sectionHeader_p->VirtualAddress,tempPE->sectionHeader_p->SizeOfRawData);
	}
	if(fileBufferSize_p){
		*fileBufferSize_p = tempPE->sectionHeader_p->PointerToRawData+tempPE->sectionHeader_p->SizeOfRawData;
	}
	return tempFileBuffer_p;
}

int RVAToFOA(char* fileBuffer_p,int RVA,wholePE* PE){
	wholePE* tempPE = PE;
	//�ж�RVA���ĸ�����
	//����RVA���ڴ��е�ƫ��offsetOfMemory
	int offsetOfMemory = RVA;
	//�ж�offsetOfMemory���ڴ��е�header�������ڽ���
	if(offsetOfMemory<tempPE->sectionHeader_p->VirtualAddress){
		//offsetOfMemory���ڴ��е�header��
		if(offsetOfMemory<tempPE->optionPEHeader_p->SizeOfHeaders){
			return offsetOfMemory;
		}else{
			return -1;
		}
	}else{
		//offsetOfMemory���ڴ��еĽ���
		for(int i=0;i<tempPE->PEHeader_p->NumberOfSections;i++){
			if(offsetOfMemory>=(tempPE->sectionHeader_p+i)->VirtualAddress && offsetOfMemory<=(tempPE->sectionHeader_p+i)->VirtualAddress+(tempPE->sectionHeader_p+i)->SizeOfRawData){
				//offsetOfMemory��i�����е���Ч��
				return (tempPE->sectionHeader_p+i)->PointerToRawData+offsetOfMemory-(tempPE->sectionHeader_p+i)->VirtualAddress;
			}
		}
	}
	return -1;
}

void isFOA(int FOA){
	if(FOA<0){
		exit(0);
	}
}




//����PE�ļ�
void analyzePE(char* fileBuffer_p,wholePE* PE){
	PE->DOSHeader_p = NULL;
	PE->NTHeader_p = NULL;
	PE->optionPEHeader_p = NULL;
	PE->PEHeader_p = NULL;
	PE->sectionHeader_p = NULL;
	//�ж�imageBuffer_p�Ƿ�Ϊ0
	if(fileBuffer_p == NULL){
		MessageBox(0,TEXT("imageBuffer��Ч��"),0,0);
		return;
	}
	//�ж��Ƿ�������Ч��MZ���
	if(*((short*)fileBuffer_p)!=0x5a4d){
		MessageBox(0,TEXT("������Ч��MZ��ǣ�"),0,0);
		return;
	}
	//ΪDOSHeader_p��ֵ
	PE->DOSHeader_p = (DOSHeader*)fileBuffer_p;
	//�ж��Ƿ�Ϊ��Ч��PE��־
	if(*((int*)(fileBuffer_p+PE->DOSHeader_p->e_lfanew))!=0x4550){
		MessageBox(0,TEXT("������Ч��PE��ǣ�"),0,0);
	}
	//ΪNTHeader_p��ֵ
	PE->NTHeader_p = (NTHeader*)(fileBuffer_p+PE->DOSHeader_p->e_lfanew);
	//ΪPEHeader_p��ֵ
	PE->PEHeader_p = (PEHeader*)(fileBuffer_p+PE->DOSHeader_p->e_lfanew+4);
	//ΪoptionPEHeader_p��ֵ
	PE->optionPEHeader_p = (optionPEHeader*)((char*)PE->PEHeader_p+0x14);
	//ΪsectionHeader_p��ֵ
	PE->sectionHeader_p = (sectionHeader*)((char*)PE->optionPEHeader_p+PE->PEHeader_p->SizeOfOptionalHeader);
}

//��ǰ�����ȡ�������г��ֵ�һ��0���±�
void getZroePosition(char* detailInfo,int count,int* currentPosition){
	for(int i=*currentPosition;i<count;i++){
		if(!detailInfo[i]){
			*currentPosition = i;
			return;
		}
	}
}
void getExportDirectory(char* detailInfo,int count,char* pImageBuffer){
	wholePE PE;
	analyzePE(pImageBuffer,&PE);
	//��ʼ��detailInfoָ�������
	memset(detailInfo,0,count);
	_IMAGE_EXPORT_DIRECTORY* exportForm_p = NULL;
	int currentIndex=0;

	exportForm_p = (_IMAGE_EXPORT_DIRECTORY*)(pImageBuffer+PE.optionPEHeader_p->DataDirectory[0].VirtualAddress);

	getZroePosition(detailInfo,count,&currentIndex);
	sprintf(detailInfo+currentIndex,"Name:%s\r\n",pImageBuffer+exportForm_p->Name);
	getZroePosition(detailInfo,count,&currentIndex);
	sprintf(detailInfo+currentIndex,"Base:%x\r\n",exportForm_p->Base);
	getZroePosition(detailInfo,count,&currentIndex);
	sprintf(detailInfo+currentIndex,"NumberOfFunctions:%x\r\n",exportForm_p->NumberOfFunctions);
	getZroePosition(detailInfo,count,&currentIndex);
	sprintf(detailInfo+currentIndex,"NumberOfNames:%x\r\n",exportForm_p->NumberOfNames);
	//�ָ���
	getZroePosition(detailInfo,count,&currentIndex);
	sprintf(detailInfo+currentIndex,"----------------------------------\r\n");
	//��ӡ�����ֵ����ĺ�����ַ
	getZroePosition(detailInfo,count,&currentIndex);
	sprintf(detailInfo+currentIndex,"�����ֵ����ĺ�����RVA��\r\n");
	for(int i=0;i<exportForm_p->NumberOfNames;i++){
		DWORD NameOrdinal = *((short*)(exportForm_p->AddressOfNameOrdinals+pImageBuffer)+i);
		getZroePosition(detailInfo,count,&currentIndex);
		char* pFunctionName = *((int*)(exportForm_p->AddressOfNames+pImageBuffer)+i)+pImageBuffer;
		int pFunctionAddr = *((int*)(exportForm_p->AddressOfFunctions+pImageBuffer)+NameOrdinal);
		sprintf(detailInfo+currentIndex,"%s  %x\r\n",pFunctionName,pFunctionAddr);
	}
}

void GetImportDetail(char* detailInfo,int count,char* pImageBuffer){

}

void codeLock(char* fileBuffer,int length){
	for(int i=0;i<length;i++){
		fileBuffer[i] = ~fileBuffer[i];
	}
}

int isOtherData(char* fileBuffer,wholePE* PE){
	for(int i=0;i<SECTION_SIZE*2;i++){
		if(*(fileBuffer+PE->DOSHeader_p->e_lfanew+Signature_SIZE+FILE_HEADER_SIZE+PE->PEHeader_p->SizeOfOptionalHeader+PE->PEHeader_p->NumberOfSections*SECTION_SIZE)!=0x0){
			return 1;
		}
	}
	return 0;
}

char* insertSection(char* fileBuffer,int length,wholePE* PE,char data[],int dataLength,int* newLength){
	int oldDataLength = dataLength;
	//�������ڵĳ��ȱ�Ϊ�ڴ�����������
	if(dataLength%PE->optionPEHeader_p->SectionAlignment!=0){
		dataLength += (PE->optionPEHeader_p->SectionAlignment - (dataLength % PE->optionPEHeader_p->SectionAlignment));
	}
	*newLength = dataLength + length;
	//�ڵ�ǰ���һ���ڵĽ���λ�����һ���½�
	char* newFileBuffer = (char*)malloc(dataLength+length);
	if(!newFileBuffer){
		exit(0);
	}
	memset(newFileBuffer,0,dataLength+length);
	for(int i=0;i<length;i++){
		newFileBuffer[i] = fileBuffer[i];
	}
	int l=0;
	for(int i=length;i<(length+oldDataLength);i++,l++){
		newFileBuffer[i] = data[l];
	}
	wholePE newPE;
	analyzePE(newFileBuffer,&newPE);
	newPE.PEHeader_p->NumberOfSections ++;	//�ڵ���Ŀ��һ
	newPE.optionPEHeader_p->SizeOfImage += (PE->optionPEHeader_p->SectionAlignment - PE->optionPEHeader_p->SizeOfImage%PE->optionPEHeader_p->SectionAlignment);
	newPE.optionPEHeader_p->SizeOfImage += dataLength;	//�����µ��ڴ��С
	if(PE->optionPEHeader_p->SizeOfHeaders-(PE->DOSHeader_p->e_lfanew+Signature_SIZE+FILE_HEADER_SIZE+PE->PEHeader_p->SizeOfOptionalHeader+PE->PEHeader_p->NumberOfSections*SECTION_SIZE)>=2*SECTION_SIZE && !isOtherData(fileBuffer,PE)){
		//�ڱ�����������ڱ��С�Ŀհ����򣬲���û����������
		sectionHeader* tempSection_p = (sectionHeader*)(newFileBuffer+(PE->DOSHeader_p->e_lfanew + Signature_SIZE + FILE_HEADER_SIZE + PE->PEHeader_p->SizeOfOptionalHeader + PE->PEHeader_p->NumberOfSections * SECTION_SIZE));

		tempSection_p->Name[0] = 'a';
		tempSection_p->Name[1] = 'a';
		tempSection_p->Name[2] = 'a';
		tempSection_p->Name[3] = 0;
		tempSection_p->Misc.VirtualSize = dataLength;
		if(PE->optionPEHeader_p->SizeOfImage%PE->optionPEHeader_p->SectionAlignment != 0){
			tempSection_p->VirtualAddress =PE->optionPEHeader_p->SizeOfImage+(PE->optionPEHeader_p->SectionAlignment - PE->optionPEHeader_p->SizeOfImage%PE->optionPEHeader_p->SectionAlignment);
		}else{
			tempSection_p->VirtualAddress =PE->optionPEHeader_p->SizeOfImage;
		}
		tempSection_p->SizeOfRawData = dataLength;
		tempSection_p->PointerToRawData = length;
		tempSection_p->Characteristics = 0x40000000;
		return newFileBuffer;
	}else{
		//�ڱ���治�������ڱ��С�Ŀհ�������ߴ�����������
		if((newPE.DOSHeader_p->e_lfanew-DOS_HEADER_SIZE)>=2*SECTION_SIZE){
			int tempL = (Signature_SIZE+FILE_HEADER_SIZE+newPE.PEHeader_p->SizeOfOptionalHeader+(newPE.PEHeader_p->NumberOfSections-1)*SECTION_SIZE);
			char* tempBuffer_p = newFileBuffer+DOS_HEADER_SIZE;
			for(int i=0;i<tempL;i++){
				*tempBuffer_p = *(newFileBuffer+newPE.DOSHeader_p->e_lfanew+i);
				tempBuffer_p ++;
			}
			//����µĽڱ�
			sectionHeader* tempSection_p = (sectionHeader*)(tempBuffer_p);
			//�ڳ�λ�ú󣬸ı�DOS��e_lfanew
			newPE.DOSHeader_p->e_lfanew = DOS_HEADER_SIZE;

			//Ϊ����ӵĽڱ�����Ը�ֵ
			sectionHeader* a = tempSection_p;
			for(int i=0;i<2;i++){
				a->Characteristics = 0;
				a->Misc.PhysicalAddress = 0;
				for(int l=0;l<8;l++){
					a->Name[l] = 0;
				}
				a->NumberOfLinenumbers = 0;
				a->NumberOfRelocations = 0;
				a->PointerToLinenumbers = 0;
				a->PointerToRawData = 0;
				a->PointerToRelocations = 0;
				a->SizeOfRawData = 0;
				a->VirtualAddress = 0;
				a++;
			}

			tempSection_p->Name[0] = 'a';
			tempSection_p->Name[1] = 'a';
			tempSection_p->Name[2] = 'a';
			tempSection_p->Name[3] = 0;
			tempSection_p->Misc.VirtualSize = dataLength;
			if(PE->optionPEHeader_p->SizeOfImage%PE->optionPEHeader_p->SectionAlignment != 0){
				tempSection_p->VirtualAddress =PE->optionPEHeader_p->SizeOfImage+(PE->optionPEHeader_p->SectionAlignment - PE->optionPEHeader_p->SizeOfImage%PE->optionPEHeader_p->SectionAlignment);
			}else{
				tempSection_p->VirtualAddress =PE->optionPEHeader_p->SizeOfImage;
			}
			tempSection_p->SizeOfRawData = dataLength;
			tempSection_p->PointerToRawData = length;
			tempSection_p->Characteristics = 0x40000000;
			return newFileBuffer;
		}else{
			MessageBox(NULL,NULL,TEXT("DOSͷ����Ŀ�������ռ䲻�㣡����"),MB_OK);
			return NULL;
		}
	}
}

void encode(char* pFileBuffer,int Size){
	char* pTempFileBuffer = pFileBuffer;
	for(int i=0;i<Size;i++){
		*pTempFileBuffer = *pTempFileBuffer^1;
		pTempFileBuffer++;
	}
}

void ProcessEncode(char SrcProcessPath[],char ShellPath[],char DstPath[]){
	wholePE PE;
	int Size;
	char* pFileBuffer = getFileContent(SrcProcessPath,&Size);
	encode(pFileBuffer,Size);

	//������
	int Size1;
	wholePE PE1;
	char* pFileBuffer1 = getFileContent(ShellPath,&Size1);
	analyzePE(pFileBuffer1,&PE1);
	int NewLength;
	char* pNewFileBuffer = insertSection(pFileBuffer1,Size1,&PE1,pFileBuffer,Size,&NewLength);
	pushContentToFile(pNewFileBuffer,NewLength,DstPath);
	free(pNewFileBuffer);
	free(pFileBuffer);
	free(pFileBuffer1);
}

bool enableDebugPriv()
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
 
    if (!OpenProcessToken(GetCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
        CloseHandle(hToken);
        return false;
    }
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }
    return true;
}

BOOL DllRemoteThreadInsert(DWORD PID,char DllPath[]){
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS,FALSE,PID);	//��ȡ���̾��
	//��ȡ�̺߳����ĵ�ַ����Ŀ�������LoadLibrary�����ĵ�ַ��һ������²�ͬ������LoadLibrary�����ĵ�ַ�����
	//printf("%x\n",LoadLibraryA);

	//���̺߳����Ĳ���д�뵽Ŀ������У�����¼��ַ
	DWORD parameterLength = strlen(DllPath) + 1;
	LPVOID parameterAddr = VirtualAllocEx(processHandle,NULL,parameterLength,MEM_COMMIT,PAGE_READWRITE);	//��Ŀ�����������ռ�
	SIZE_T size_t;
	if(!WriteProcessMemory(processHandle,parameterAddr,DllPath,parameterLength,&size_t)){	//��Ŀ�������д������
		 //printf("д���ڴ�ʧ��\n");
		 return 0;
	}

	//��Ŀ������д���һ���߳�
	HANDLE threadHandle = CreateRemoteThread(processHandle,NULL,0,(LPTHREAD_START_ROUTINE )LoadLibraryA,parameterAddr,0,NULL);
	if(!threadHandle){
		return 0;
	}

	//�ȴ��̺߳�����������ȡ�߳��˳��룬��LoadLibrary�ķ���ֵ����dll���׵�ַ
	if(WaitForSingleObject(threadHandle,INFINITE)==WAIT_FAILED){	//�ȴ��̺߳�������
		//printf("��������\n");
		return 0;
	}
	DWORD exitCode;
	if(!GetExitCodeThread(threadHandle,&exitCode)){	//��ȡ�߳��˳���
		//printf("��ȡ�߳��˳������\n");
		return 0;
	}

	if(!VirtualFreeEx(processHandle,parameterAddr,0,MEM_RELEASE)){	//�ͷ�Ϊdll��������Ŀռ�
		printf("�ͷŲ�����ַʧ��\n");
		return 1;
	}

	//�رմ򿪵ľ��
	CloseHandle(processHandle);	
	CloseHandle(threadHandle);

	return 1;
}

#endif