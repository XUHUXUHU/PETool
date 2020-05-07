#if !defined (STRCUTOFPE_H) //防止Num_add.h在别的文件里多次声明
#define STRCUTOFPE_H
//定义DOS头结构体
#define DOS_HEADER_SIZE 0x40
#define SECTION_SIZE 0x28
#define FILE_HEADER_SIZE 0x14
#define Signature_SIZE 0x4
struct DOSHeader{
	short e_magic; 	//"MZ标记"用于判断是否为可执行文件
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
	int e_lfanew; 	//PE头相对于文件的偏移，用于定位PE文件
};
//NT头结构体
struct NTHeader{
	int  Signature;	//"PE标记"
};
//定义PE头结构体
struct PEHeader{
	short Machine; 	//程序运行的CPU型号：0x0任何处理器/0x14C 386及后续处理器
	short NumberOfSections; //文件中存在的节的总数，如果要新增节或者合并节 就要修改这个值
	int TimeDateStamp; //时间戳：文件创建的时间（和操作系统的创建时间），编译器填写的
	int PointerToSymbolTable; 
    int NumberOfSymbols; 
	short SizeOfOptionalHeader; //可选PE头的大小，32位PE文件默认E0h 64位PE文件默认为F0h 大小可以自定义
	short Characteristics; //每个位有不同的含义，可执行文件值为10F 即0 1 2 3 8 位 置1
};
//定义可选PE头结构体
struct _IMAGE_DATA_DIRECTORY_SELF { 
	int VirtualAddress; 
	int Size; 
};

struct optionPEHeader{
	short Magic; //说明文件类型：10B 32位下的PE文件 20B 64位下的PE文件
	char MajorLinkerVersion; 
    char MinorLinkerVersion; 
	int SizeOfCode; //所有代码节的和，必须时FileAlignment的整数倍 编译器填的 没用
	int SizeOfInitializedData; //已初始化数据大小的和，必须时FileAlignment的整数倍 编译器填的 没用
	int SizeOfUninitializedData; //未初始化数据大小的和，必须时FIleAlignment的整数倍 编译器填的 没用
	int AddressOfEntryPoint; //程序入口
	int BaseOfCode; //代码开始的基址，编译器填的 没用
	int BaseOfData; //数据开始的基址，编译器填的 没用
	int ImageBase; //内存镜像基址
	int SectionAlignment; //内存对齐
	int FileAlignment; //文件对齐
	short MajorOperatingSystemVersion; 
	short MinorOperatingSystemVersion; 
	short MajorImageVersion; 
	short MinorImageVersion; 
	short MajorSubsystemVersion; 
	short MinorSubsystemVersion; 
	int Win32VersionValue; 
	int SizeOfImage; //内存中整个PE文件的映射的尺寸，可以比实际的值大，但是必须是SectionAlignment的整数倍
	int SizeOfHeaders; //所有头+节表按照文件对齐后的大小，严格按照FileAligment对齐，否则加载会出错
	int CheckSum; //校验和，一些系统文件有要求，来判断文件是否被修改 
	short Subsystem; 
	short DllCharacteristics; 
	int SizeOfStackReserve; //初始化时保留的堆栈大小
	int SizeOfStackCommit; //初始化时实际提交的大小
	int SizeOfHeapReserve; //初始化时保留的堆的大小
	int SizeOfHeapCommit; //初始化时实际提交的大小
	int LoaderFlags; 
	int NumberOfRvaAndSizes; //目录项数目，就是下面的16
	_IMAGE_DATA_DIRECTORY_SELF DataDirectory[16]; 
};
//定义节表结构体
struct sectionHeader{
	char Name[8]; //该节的名字，可以随便改，只取前8个字节
	union { 
		int PhysicalAddress; 
		int VirtualSize; 
	} Misc; //该节在内存中没有对齐前的真实尺寸，该值可以不准确
	int VirtualAddress; //该节在内存中的偏移，相对于imagebase
	int SizeOfRawData; //节在文件中对齐后的尺寸
	int PointerToRawData; //节在文件中的偏移
	int PointerToRelocations; //在obj文件中使用 对exe没用
	int PointerToLinenumbers; //行号表的位置，调试的时候使用
	short  NumberOfRelocations; //在obj中使用，对exe无用
	short  NumberOfLinenumbers; //行号表中行号的的数量，调试的时候使用
	int Characteristics; //节的属性
};

//定义PE的整个头部的结构体
struct wholePE {
	struct DOSHeader* DOSHeader_p;
	struct NTHeader* NTHeader_p;
	struct PEHeader* PEHeader_p;
	struct optionPEHeader* optionPEHeader_p;
	struct sectionHeader* sectionHeader_p;		//第一个节表的指针
};

//定义导出表结构
struct _IMAGE_EXPORT_DIRECTORY_SELF { 
	int Characteristics; 
	int TimeDateStamp; 
	short MajorVersion; 
	short MinorVersion; 
	int Name;  //指向该导出表文件名字符串
	int Base; //导出函数起始序号
	int NumberOfFunctions;  //导出函数地址表中函数的个数 //不一定是真正导出函数的个数。.def文件中用 （最大的序号-最小的序号+1）个函数。
	int NumberOfNames; //函数名字个数
	int AddressOfFunctions; //导出函数地址表RVA
	int AddressOfNames; //导出函数名称表RVA
	int AddressOfNameOrdinals; //导出函数序号表RVA
};

//定义重定位表结构
struct _IMAGE_BASE_RELOCATION_SELF{
	int VirtualAddress;
	int SizeOfBlock;
};

//定义导入表结构
struct _IMAGE_IMPORT_DESCRIPTOR_SELF { 
	union { 
		int Characteristics;                
		int OriginalFirstThunk;//RVA 指向IMAGE_THUNK_DATA（INT）结构数组
	} u; 
	int TimeDateStamp; //时间戳
	int ForwarderChain; 
	int Name; //RVA，指向dll名字，该名字以0结尾
	int FirstThunk; //RVA，指向IMAGE_THUNK_DATA结构数组（IAT）
};

//定义IAT表和INT表结构
struct _IMAGE_THUNK_DATA {
	union {
		int ForwarderString;
		int Function;
		int Ordinal;	//序号
		int AddressOfData;//指向IMPORT_BY_NAME
	}u1;
};

//定义_IMAGE_IMPORT_BY_NAME 
 struct _IMAGE_IMPORT_BY_NAME_SELF {
	 short Hint;
	 char Name[1];
 };





#endif