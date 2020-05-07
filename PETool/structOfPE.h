#if !defined (STRCUTOFPE_H) //��ֹNum_add.h�ڱ���ļ���������
#define STRCUTOFPE_H
//����DOSͷ�ṹ��
#define DOS_HEADER_SIZE 0x40
#define SECTION_SIZE 0x28
#define FILE_HEADER_SIZE 0x14
#define Signature_SIZE 0x4
struct DOSHeader{
	short e_magic; 	//"MZ���"�����ж��Ƿ�Ϊ��ִ���ļ�
	short e_cblp; 	
	short e_cp; 
	short e_crlc; 
	short e_cparhdr; 
	short e_minalloc; 
	short e_maxalloc; 
	short e_ss; 
	short e_sp; 
	short e_csum; 
	short e_ip; 
	short e_cs; 
	short e_lfarlc; 
	short e_ovno; 
	short e_res[4]; 
	short e_oemid; 
	short e_oeminfo; 
	short e_res2[10]; 
	int e_lfanew; 	//PEͷ������ļ���ƫ�ƣ����ڶ�λPE�ļ�
};
//NTͷ�ṹ��
struct NTHeader{
	int  Signature;	//"PE���"
};
//����PEͷ�ṹ��
struct PEHeader{
	short Machine; 	//�������е�CPU�ͺţ�0x0�κδ�����/0x14C 386������������
	short NumberOfSections; //�ļ��д��ڵĽڵ����������Ҫ�����ڻ��ߺϲ��� ��Ҫ�޸����ֵ
	int TimeDateStamp; //ʱ������ļ�������ʱ�䣨�Ͳ���ϵͳ�Ĵ���ʱ�䣩����������д��
	int PointerToSymbolTable; 
    int NumberOfSymbols; 
	short SizeOfOptionalHeader; //��ѡPEͷ�Ĵ�С��32λPE�ļ�Ĭ��E0h 64λPE�ļ�Ĭ��ΪF0h ��С�����Զ���
	short Characteristics; //ÿ��λ�в�ͬ�ĺ��壬��ִ���ļ�ֵΪ10F ��0 1 2 3 8 λ ��1
};
//�����ѡPEͷ�ṹ��
struct _IMAGE_DATA_DIRECTORY_SELF { 
	int VirtualAddress; 
	int Size; 
};

struct optionPEHeader{
	short Magic; //˵���ļ����ͣ�10B 32λ�µ�PE�ļ� 20B 64λ�µ�PE�ļ�
	char MajorLinkerVersion; 
    char MinorLinkerVersion; 
	int SizeOfCode; //���д���ڵĺͣ�����ʱFileAlignment�������� ��������� û��
	int SizeOfInitializedData; //�ѳ�ʼ�����ݴ�С�ĺͣ�����ʱFileAlignment�������� ��������� û��
	int SizeOfUninitializedData; //δ��ʼ�����ݴ�С�ĺͣ�����ʱFIleAlignment�������� ��������� û��
	int AddressOfEntryPoint; //�������
	int BaseOfCode; //���뿪ʼ�Ļ�ַ����������� û��
	int BaseOfData; //���ݿ�ʼ�Ļ�ַ����������� û��
	int ImageBase; //�ڴ澵���ַ
	int SectionAlignment; //�ڴ����
	int FileAlignment; //�ļ�����
	short MajorOperatingSystemVersion; 
	short MinorOperatingSystemVersion; 
	short MajorImageVersion; 
	short MinorImageVersion; 
	short MajorSubsystemVersion; 
	short MinorSubsystemVersion; 
	int Win32VersionValue; 
	int SizeOfImage; //�ڴ�������PE�ļ���ӳ��ĳߴ磬���Ա�ʵ�ʵ�ֵ�󣬵��Ǳ�����SectionAlignment��������
	int SizeOfHeaders; //����ͷ+�ڱ����ļ������Ĵ�С���ϸ���FileAligment���룬������ػ����
	int CheckSum; //У��ͣ�һЩϵͳ�ļ���Ҫ�����ж��ļ��Ƿ��޸� 
	short Subsystem; 
	short DllCharacteristics; 
	int SizeOfStackReserve; //��ʼ��ʱ�����Ķ�ջ��С
	int SizeOfStackCommit; //��ʼ��ʱʵ���ύ�Ĵ�С
	int SizeOfHeapReserve; //��ʼ��ʱ�����ĶѵĴ�С
	int SizeOfHeapCommit; //��ʼ��ʱʵ���ύ�Ĵ�С
	int LoaderFlags; 
	int NumberOfRvaAndSizes; //Ŀ¼����Ŀ�����������16
	_IMAGE_DATA_DIRECTORY_SELF DataDirectory[16]; 
};
//����ڱ�ṹ��
struct sectionHeader{
	char Name[8]; //�ýڵ����֣��������ģ�ֻȡǰ8���ֽ�
	union { 
		int PhysicalAddress; 
		int VirtualSize; 
	} Misc; //�ý����ڴ���û�ж���ǰ����ʵ�ߴ磬��ֵ���Բ�׼ȷ
	int VirtualAddress; //�ý����ڴ��е�ƫ�ƣ������imagebase
	int SizeOfRawData; //�����ļ��ж����ĳߴ�
	int PointerToRawData; //�����ļ��е�ƫ��
	int PointerToRelocations; //��obj�ļ���ʹ�� ��exeû��
	int PointerToLinenumbers; //�кű��λ�ã����Ե�ʱ��ʹ��
	short  NumberOfRelocations; //��obj��ʹ�ã���exe����
	short  NumberOfLinenumbers; //�кű����кŵĵ����������Ե�ʱ��ʹ��
	int Characteristics; //�ڵ�����
};

//����PE������ͷ���Ľṹ��
struct wholePE {
	struct DOSHeader* DOSHeader_p;
	struct NTHeader* NTHeader_p;
	struct PEHeader* PEHeader_p;
	struct optionPEHeader* optionPEHeader_p;
	struct sectionHeader* sectionHeader_p;		//��һ���ڱ��ָ��
};

//���嵼����ṹ
struct _IMAGE_EXPORT_DIRECTORY_SELF { 
	int Characteristics; 
	int TimeDateStamp; 
	short MajorVersion; 
	short MinorVersion; 
	int Name;  //ָ��õ������ļ����ַ���
	int Base; //����������ʼ���
	int NumberOfFunctions;  //����������ַ���к����ĸ��� //��һ�����������������ĸ�����.def�ļ����� ���������-��С�����+1����������
	int NumberOfNames; //�������ָ���
	int AddressOfFunctions; //����������ַ��RVA
	int AddressOfNames; //�����������Ʊ�RVA
	int AddressOfNameOrdinals; //����������ű�RVA
};

//�����ض�λ��ṹ
struct _IMAGE_BASE_RELOCATION_SELF{
	int VirtualAddress;
	int SizeOfBlock;
};

//���嵼���ṹ
struct _IMAGE_IMPORT_DESCRIPTOR_SELF { 
	union { 
		int Characteristics;                
		int OriginalFirstThunk;//RVA ָ��IMAGE_THUNK_DATA��INT���ṹ����
	} u; 
	int TimeDateStamp; //ʱ���
	int ForwarderChain; 
	int Name; //RVA��ָ��dll���֣���������0��β
	int FirstThunk; //RVA��ָ��IMAGE_THUNK_DATA�ṹ���飨IAT��
};

//����IAT���INT��ṹ
struct _IMAGE_THUNK_DATA {
	union {
		int ForwarderString;
		int Function;
		int Ordinal;	//���
		int AddressOfData;//ָ��IMPORT_BY_NAME
	}u1;
};

//����_IMAGE_IMPORT_BY_NAME 
 struct _IMAGE_IMPORT_BY_NAME_SELF {
	 short Hint;
	 char Name[1];
 };





#endif