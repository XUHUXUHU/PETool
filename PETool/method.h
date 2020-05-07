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
    long length=ftell(fp);		//ftell计算出文件的长度
	fseek(fp,0,SEEK_SET);
	char* p = (char*)malloc(length);
	if(!p){
		MessageBox(0,TEXT("分配空间失败！"),0,0);
		fclose(fp);
		return 0;
	}
	//将文件读取到缓冲区
	int isGetContent = fread(p,length,1,fp);
	if(!isGetContent){
		MessageBox(0,TEXT("读取数据失败！"),0,0);
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
		printf("为ImageBuffer分配空间失败！");
		return 0;
	}
	//初始化分配到的内存
	memset(tempImageBuffer_p,0,tempPE->optionPEHeader_p->SizeOfImage);
	//根据SizeOfHeaders先Copy头
	memcpy(tempImageBuffer_p,fileBuffer_p,tempPE->optionPEHeader_p->SizeOfHeaders);
	//根据节表，循环copy节
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
	//判断RVA在哪个区域
	//计算RVA在内存中的偏移offsetOfMemory
	int offsetOfMemory = RVA;
	//判断offsetOfMemory在内存中的header区还是在节区
	if(offsetOfMemory<tempPE->sectionHeader_p->VirtualAddress){
		//offsetOfMemory在内存中的header区
		if(offsetOfMemory<tempPE->optionPEHeader_p->SizeOfHeaders){
			return offsetOfMemory;
		}else{
			return -1;
		}
	}else{
		//offsetOfMemory在内存中的节区
		for(int i=0;i<tempPE->PEHeader_p->NumberOfSections;i++){
			if(offsetOfMemory>=(tempPE->sectionHeader_p+i)->VirtualAddress && offsetOfMemory<=(tempPE->sectionHeader_p+i)->VirtualAddress+(tempPE->sectionHeader_p+i)->SizeOfRawData){
				//offsetOfMemory在i个节中的有效区
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




//解析PE文件
void analyzePE(char* fileBuffer_p,wholePE* PE){
	PE->DOSHeader_p = NULL;
	PE->NTHeader_p = NULL;
	PE->optionPEHeader_p = NULL;
	PE->PEHeader_p = NULL;
	PE->sectionHeader_p = NULL;
	//判断imageBuffer_p是否为0
	if(fileBuffer_p == NULL){
		MessageBox(0,TEXT("imageBuffer无效！"),0,0);
		return;
	}
	//判断是否是是有效的MZ标记
	if(*((short*)fileBuffer_p)!=0x5a4d){
		MessageBox(0,TEXT("不是有效的MZ标记！"),0,0);
		return;
	}
	//为DOSHeader_p赋值
	PE->DOSHeader_p = (DOSHeader*)fileBuffer_p;
	//判断是否为有效的PE标志
	if(*((int*)(fileBuffer_p+PE->DOSHeader_p->e_lfanew))!=0x4550){
		MessageBox(0,TEXT("不是有效的PE标记！"),0,0);
	}
	//为NTHeader_p赋值
	PE->NTHeader_p = (NTHeader*)(fileBuffer_p+PE->DOSHeader_p->e_lfanew);
	//为PEHeader_p赋值
	PE->PEHeader_p = (PEHeader*)(fileBuffer_p+PE->DOSHeader_p->e_lfanew+4);
	//为optionPEHeader_p赋值
	PE->optionPEHeader_p = (optionPEHeader*)((char*)PE->PEHeader_p+0x14);
	//为sectionHeader_p赋值
	PE->sectionHeader_p = (sectionHeader*)((char*)PE->optionPEHeader_p+PE->PEHeader_p->SizeOfOptionalHeader);
}

//从前往后获取到数组中出现第一个0的下标
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
	//初始化detailInfo指向的数组
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
	//分割线
	getZroePosition(detailInfo,count,&currentIndex);
	sprintf(detailInfo+currentIndex,"----------------------------------\r\n");
	//打印以名字导出的函数地址
	getZroePosition(detailInfo,count,&currentIndex);
	sprintf(detailInfo+currentIndex,"以名字导出的函数的RVA：\r\n");
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
	//将新增节的长度变为内存对齐的整数倍
	if(dataLength%PE->optionPEHeader_p->SectionAlignment!=0){
		dataLength += (PE->optionPEHeader_p->SectionAlignment - (dataLength % PE->optionPEHeader_p->SectionAlignment));
	}
	*newLength = dataLength + length;
	//在当前最后一个节的结束位置添加一个新节
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
	newPE.PEHeader_p->NumberOfSections ++;	//节的数目加一
	newPE.optionPEHeader_p->SizeOfImage += (PE->optionPEHeader_p->SectionAlignment - PE->optionPEHeader_p->SizeOfImage%PE->optionPEHeader_p->SectionAlignment);
	newPE.optionPEHeader_p->SizeOfImage += dataLength;	//设置新的内存大小
	if(PE->optionPEHeader_p->SizeOfHeaders-(PE->DOSHeader_p->e_lfanew+Signature_SIZE+FILE_HEADER_SIZE+PE->PEHeader_p->SizeOfOptionalHeader+PE->PEHeader_p->NumberOfSections*SECTION_SIZE)>=2*SECTION_SIZE && !isOtherData(fileBuffer,PE)){
		//节表后面有两个节表大小的空白区域，并且没有其他数据
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
		//节表后面不够两个节表大小的空白区域或者存在其他数据
		if((newPE.DOSHeader_p->e_lfanew-DOS_HEADER_SIZE)>=2*SECTION_SIZE){
			int tempL = (Signature_SIZE+FILE_HEADER_SIZE+newPE.PEHeader_p->SizeOfOptionalHeader+(newPE.PEHeader_p->NumberOfSections-1)*SECTION_SIZE);
			char* tempBuffer_p = newFileBuffer+DOS_HEADER_SIZE;
			for(int i=0;i<tempL;i++){
				*tempBuffer_p = *(newFileBuffer+newPE.DOSHeader_p->e_lfanew+i);
				tempBuffer_p ++;
			}
			//添加新的节表
			sectionHeader* tempSection_p = (sectionHeader*)(tempBuffer_p);
			//腾出位置后，改变DOS的e_lfanew
			newPE.DOSHeader_p->e_lfanew = DOS_HEADER_SIZE;

			//为新添加的节表的属性赋值
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
			MessageBox(NULL,NULL,TEXT("DOS头后面的可用区域空间不足！！！"),MB_OK);
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

	//新增节
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
	HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS,FALSE,PID);	//获取进程句柄
	//获取线程函数的地址，即目标进程中LoadLibrary函数的地址，一般情况下不同进程中LoadLibrary函数的地址都相等
	//printf("%x\n",LoadLibraryA);

	//将线程函数的参数写入到目标进程中，并记录地址
	DWORD parameterLength = strlen(DllPath) + 1;
	LPVOID parameterAddr = VirtualAllocEx(processHandle,NULL,parameterLength,MEM_COMMIT,PAGE_READWRITE);	//在目标进程中申请空间
	SIZE_T size_t;
	if(!WriteProcessMemory(processHandle,parameterAddr,DllPath,parameterLength,&size_t)){	//在目标进程中写入数据
		 //printf("写入内存失败\n");
		 return 0;
	}

	//在目标程序中创建一个线程
	HANDLE threadHandle = CreateRemoteThread(processHandle,NULL,0,(LPTHREAD_START_ROUTINE )LoadLibraryA,parameterAddr,0,NULL);
	if(!threadHandle){
		return 0;
	}

	//等待线程函数结束，获取线程退出码，即LoadLibrary的返回值，即dll的首地址
	if(WaitForSingleObject(threadHandle,INFINITE)==WAIT_FAILED){	//等待线程函数结束
		//printf("函数错误\n");
		return 0;
	}
	DWORD exitCode;
	if(!GetExitCodeThread(threadHandle,&exitCode)){	//获取线程退出码
		//printf("获取线程退出码错误\n");
		return 0;
	}

	if(!VirtualFreeEx(processHandle,parameterAddr,0,MEM_RELEASE)){	//释放为dll名字申请的空间
		printf("释放参数地址失败\n");
		return 1;
	}

	//关闭打开的句柄
	CloseHandle(processHandle);	
	CloseHandle(threadHandle);

	return 1;
}

#endif