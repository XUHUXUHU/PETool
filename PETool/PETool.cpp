// PETool.cpp : 定义应用程序的入口点。
//

#include "stdafx.h"
#include "PETool.h"

//主界面消息处理函数
INT_PTR CALLBACK MainDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
);
//PE查看器消息处理函数
INT_PTR CALLBACK messgeCheckDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
);
//PE查看器的节消息处理函数
INT_PTR CALLBACK SectionDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
);
INT_PTR CALLBACK DirectionDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
);
INT_PTR CALLBACK detailDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
);
void InitProcessListView(HWND hwndDlg);
void InitModulesListView(HWND hwndDlg);
void EnumProcess(HWND hListProcess);
void EnumProcessModule(HWND hListProcess,HWND hListModule,WPARAM wParam,LPARAM lParam);
void setTheValueForPECheck(HWND hwndDlg);
void InitSectionListView(HWND hwndDlg);
void getSectionInfo(HWND hSectionDlg);
void InitDirectionView(HWND hwndDlg);

#define DetailBufferSize 4096

HINSTANCE hAppInstance;	//存储全局程序句柄
char FileName[256];		//存储解析文件时被选择的文件名
struct wholePE PE;		//存储储解析文件时PE文件被解析后的PE结构
char* fileBuffer_p;		//存储储解析文件时被选中的PE文件的fileBuffer
char* pImageBuffer;	//存储解析文件时被选中的PE文件的pImageBufer
char detailBuffer[DetailBufferSize];	//存储储解析文件时详细信息中的信息
char* ShellPath = "F:\\VSC++\\PETool\\Debug\\shell4.exe";
//char FileNameOfShell[256];	//存储程序加壳时被选择的文件名
DWORD dwPID = -1;	//被选中行的PID

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	hAppInstance = hInstance;
	
	//声明我需要加载的通用控件的类
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icex);

	//将对话框创建出来
	DialogBox(hInstance,MAKEINTRESOURCE(IDD_DIALOG_MAIN),NULL,MainDlgProc);

	if(fileBuffer_p!=NULL){
		free(fileBuffer_p);
	}
	return 0;
}

INT_PTR CALLBACK MainDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
)
{
	OPENFILENAMEA stOpenFile;
	switch(uMsg){
	case WM_CLOSE:
		{
			//关闭对话框
			EndDialog(hwndDlg,0);
			break;
		}
	case WM_INITDIALOG:
		{
			/*
			//加载图标
			HICON hIcon = LoadIcon(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_MAIN));
			//设置图标
			SendMessage(hwndDlg,WM_SETICON,ICON_BIG,(long)hIcon);
			SendMessage(hwndDlg,WM_SETICON,ICON_SMALL,(long)hIcon);
			*/
			//设置ProcessListView的风格
			InitProcessListView(hwndDlg);
			InitModulesListView(hwndDlg);
			break;
		}
	case WM_NOTIFY:
		{
			NMHDR* pNMHDR = (NMHDR*)lParam;
			if(wParam == IDC_LIST_PROCESS && pNMHDR->code == NM_CLICK){
				EnumProcessModule(GetDlgItem(hwndDlg,IDC_LIST_PROCESS),GetDlgItem(hwndDlg,IDC_LIST_MODOULE),wParam,lParam);
			}
			break;
		}
	case WM_COMMAND:
		{
		switch(LOWORD(wParam))
		{
		//PE查看器
		case IDC_BUTTON_PECheck:
			{
				CHAR szPeFileExt[100] = "*.exe;*.dll;*.scr;*.drv;*.sys";
				CHAR szFileName[256];
				memset(szFileName,0,256);
				memset(&stOpenFile,0,sizeof(OPENFILENAME));
				stOpenFile.lStructSize = sizeof(OPENFILENAME);
				stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
				stOpenFile.hwndOwner = hwndDlg;
				stOpenFile.lpstrFilter = szPeFileExt;
				stOpenFile.lpstrFile = szFileName;
				stOpenFile.nMaxFile = MAX_PATH;

				if(GetOpenFileNameA(&stOpenFile)){
					//MessageBoxA(0,szFileName,0,0);
					for(int i=0;i<256;i++){
						FileName[i] = szFileName[i];
					}
					//打开新的对话框
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_messgeCheck),hwndDlg,messgeCheckDlgProc);
				}

				return TRUE;
			}
		//软件加壳
		case IDC_BUTTON_Shell:
			{
				CHAR szPeFileExt[100] = "*.exe";
				CHAR szFileName[256];
				memset(szFileName,0,256);
				memset(&stOpenFile,0,sizeof(OPENFILENAME));
				stOpenFile.lStructSize = sizeof(OPENFILENAME);
				stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
				stOpenFile.hwndOwner = hwndDlg;
				stOpenFile.lpstrFilter = szPeFileExt;
				stOpenFile.lpstrFile = szFileName;
				stOpenFile.nMaxFile = MAX_PATH;

				if(GetOpenFileNameA(&stOpenFile)){
					int len = strlen(szFileName);
					char* DstPath = (char*)malloc(len+2);
					memset(DstPath,0,len+2);
					strcpy(DstPath,szFileName);
					strcpy(DstPath+len-4,"1.exe");
					ProcessEncode(szFileName,ShellPath,DstPath);
				}
				return TRUE;
			}
		//dll注入
		case IDC_BUTTON_DLLInsert:
			{
				CHAR szPeFileExt[100] = "*.exe";
				CHAR szFileName[256];
				memset(szFileName,0,256);
				memset(&stOpenFile,0,sizeof(OPENFILENAME));
				stOpenFile.lStructSize = sizeof(OPENFILENAME);
				stOpenFile.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
				stOpenFile.hwndOwner = hwndDlg;
				stOpenFile.lpstrFilter = szPeFileExt;
				stOpenFile.lpstrFile = szFileName;
				stOpenFile.nMaxFile = MAX_PATH;

				if(GetOpenFileNameA(&stOpenFile)){
					if(DllRemoteThreadInsert(dwPID,szFileName)){
						MessageBoxA(NULL,"注入成功","",MB_OK);
					}else{
						MessageBoxA(NULL,"注入失败","",MB_OK);
					}
				}
				return TRUE;
			}
		case IDC_BUTTON_Update:
			{
				EnumProcess(GetDlgItem(hwndDlg,IDC_LIST_PROCESS));	//更新ProcessListView中的内容
				return TRUE;
			}
		case IDC_BUTTON_About:
			{
				return TRUE;
			}
		case IDC_BUTTON_Exit:
			{
				EndDialog(hwndDlg,0);
				return TRUE;
			}
		default:
			{
				break;
			}
		}
		}
	default:
		{
			break;
		}
		}
	
	return FALSE;
}

//PE信息查看消息处理函数
INT_PTR CALLBACK messgeCheckDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
){
	switch(uMsg){
	case WM_CLOSE:
		{
			//关闭对话框
			EndDialog(hwndDlg,0);
			break;
		}
	case WM_INITDIALOG:
		{
			//打开PE文件 获取相关信息
			//TCHAR szBuffer[128];
			//wsprintf(szBuffer,TEXT("%x\n"),"00418347");
			//SendDlgItemMessage(hwndDlg,IDC_EDIT_rukou,WM_SETTEXT,0,(DWORD)szBuffer);
			int fileBufferSize;
			fileBuffer_p = getFileContent(FileName,&fileBufferSize);
			analyzePE(fileBuffer_p,&PE);
			pImageBuffer = fileBufferToImageBuffer(fileBuffer_p,&fileBufferSize,&PE);

			TCHAR szBuffer[128];
			//入口点
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->AddressOfEntryPoint);
			//SendDlgItemMessage(hwndDlg,IDC_EDIT_rukou,WM_SETTEXT,0,szBuffer);
			SetWindowText(GetDlgItem(hwndDlg,IDC_EDIT_rukou),szBuffer);

			//镜像基址
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->ImageBase);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_imageBase,WM_SETTEXT,0,(DWORD)szBuffer);

			//镜像大小
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->SizeOfImage);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_imageSize,WM_SETTEXT,0,(DWORD)szBuffer);

			//代码基址
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->BaseOfCode);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_codeBase,WM_SETTEXT,0,(DWORD)szBuffer);

			//数据基质
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->BaseOfData);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_dataBase,WM_SETTEXT,0,(DWORD)szBuffer);

			//内存对齐
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->SectionAlignment);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_memoAlign,WM_SETTEXT,0,(DWORD)szBuffer);

			//文件对齐
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->FileAlignment);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_fileAlign,WM_SETTEXT,0,(DWORD)szBuffer);

			//标志字
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->Magic);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_flagWord,WM_SETTEXT,0,(DWORD)szBuffer);

			//子系统
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->Subsystem);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_childSys,WM_SETTEXT,0,(DWORD)szBuffer);

			//区段数目
			wsprintf(szBuffer,TEXT("%x\n"),PE.PEHeader_p->NumberOfSections);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_quduanNum,WM_SETTEXT,0,(DWORD)szBuffer);

			//时间戳
			wsprintf(szBuffer,TEXT("%x\n"),PE.PEHeader_p->TimeDateStamp);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_timeNode,WM_SETTEXT,0,(DWORD)szBuffer);

			//PE头大小
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->SizeOfHeaders);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_PEHeaderSize,WM_SETTEXT,0,(DWORD)szBuffer);

			//特征值
			wsprintf(szBuffer,TEXT("%x\n"),PE.PEHeader_p->Characteristics);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_tezhengNum,WM_SETTEXT,0,(DWORD)szBuffer);

			//校验和
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->CheckSum);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_sum,WM_SETTEXT,0,(DWORD)szBuffer);

			//可选PE头
			wsprintf(szBuffer,TEXT("%x\n"),PE.PEHeader_p->SizeOfOptionalHeader);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_optionPE,WM_SETTEXT,0,(DWORD)szBuffer);

			//目录项数目
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->NumberOfRvaAndSizes);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_muluNum,WM_SETTEXT,0,(DWORD)szBuffer);

			break;
		}
	case WM_COMMAND:
		{
		switch(LOWORD(wParam))
		{
		//PE查看器
		case IDC_BUTTON_close:
			{
				EndDialog(hwndDlg,0);
				return TRUE;
			}
		case IDC_BUTTON_quduan:
			{
				//区段
				//打开新的对话框
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_SetionDIALOG),hwndDlg,SectionDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_mulu:
			{
				//目录
				//打开新的对话框
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_directory),hwndDlg,DirectionDlgProc);
				return TRUE;
			}
		default:
			{
				break;
			}
		}
		}
	default:
		{
			break;
		}
		}
	
	return FALSE;
}

INT_PTR CALLBACK SectionDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
){
	switch(uMsg){
	case WM_CLOSE:
		{
			//关闭对话框
			EndDialog(hwndDlg,0);
			break;
		}
	case WM_INITDIALOG:
		{
			//初始化节表的List View
			InitSectionListView(hwndDlg);
			break;
		}
	default:
		{
			break;
		}
		}
	
	return FALSE;
}

INT_PTR CALLBACK DirectionDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
){
	switch(uMsg){
	case WM_CLOSE:
		{
			//关闭对话框
			EndDialog(hwndDlg,0);
			break;
		}
	case WM_INITDIALOG:
		{
			InitDirectionView(hwndDlg);
			break;
		}
	case WM_COMMAND:
		{
		switch(LOWORD(wParam))
		{
		//PE查看器
		case IDC_BUTTON_DirectoryClose:
			{
				EndDialog(hwndDlg,0);
				return TRUE;
			}
		case IDC_BUTTON_derectory_exportDetail:
			{
				//设置详细信息框中的信息
				getExportDirectory(detailBuffer,4096,pImageBuffer);
				//打开新的对话框
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_directory_importDetail:
			{
				//打开新的对话框
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_directory_resourceDetail:
			{
				//打开新的对话框
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_directory_relocationDetail:
			{
				//打开新的对话框
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_directory_bindDetail:
			{
				//打开新的对话框
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_directory_IATDetail:
			{
				//打开新的对话框
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		default:
			{
				break;
			}
		}
		}
	default:
		{
			break;
		}
		}
	
	return FALSE;
}

INT_PTR CALLBACK detailDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
){
	switch(uMsg){
	case WM_CLOSE:
		{
			//关闭对话框
			EndDialog(hwndDlg,0);
			break;
		}
	case WM_INITDIALOG:
		{
			
			//SetWindowLong(hwndDlg,0,ES_MULTILINE);
			//SetWindowLong(hwndDlg,IDC_EDIT_PE_detail,ES_WANTRETURN);
			SetDlgItemTextA(hwndDlg,IDC_EDIT_PE_detail,detailBuffer);	//在edit control中\r\n表示换行
			//清零detailInfo指向的数组
			memset(detailBuffer,0,DetailBufferSize);
			//SendDlgItemMessageA(hwndDlg,IDC_EDIT_PE_detail,WM_SETTEXT,0,(DWORD)detailBuffer);
			break;
		}
	default:
		{
			break;
		}
		}
	
	return FALSE;
}

void InitProcessListView(HWND hwndDlg){
	LV_COLUMN lv;
	HWND hListProcess;

	//初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	//获取IDC_LIST_PROCESS句柄
	hListProcess = GetDlgItem(hwndDlg,IDC_LIST_PROCESS);
	//设置整行选中
	//SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,NULL);
	ListView_SetExtendedListViewStyle(hListProcess,LVS_EX_FULLROWSELECT);

	//第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("进程");	//列标题
	lv.cx = 100;	//列宽
	lv.iSubItem = 0;
	//ListView_InsertColumn(hListProcess,0,&lv);
	SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第二列
	lv.pszText = TEXT("PID");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess,1,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第三列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("镜像基址");	//列标题
	lv.cx = 100;	//列宽
	lv.iSubItem = 2;	//子项索引
	ListView_InsertColumn(hListProcess,2,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第四列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("镜像大小");	//列标题
	lv.cx = 100;	//列宽
	lv.iSubItem = 3;
	ListView_InsertColumn(hListProcess,3,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);

	EnumProcess(hListProcess);
}

void EnumProcess(HWND hListProcess){
	SendMessage(hListProcess, LVM_DELETEALLITEMS, 0, 0);//删除所有行
	//调用API 查出系统中的进程信息
	PROCESSENTRY32 pe32;
	memset(&pe32,0,sizeof(PROCESSENTRY32));
	//在使用这个结构之前，先设置它的大小
	pe32.dwSize = sizeof(pe32);
	//给系统内所有的进程拍一个快照
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot调用失败\n");
		return;
	}
	//遍历进程快照，轮流显示每个进程的信息
	BOOL bMore = ::Process32First(hProcessSnap,&pe32);
	int i=0;
	while(bMore)
	{
		//获取进程的模块
		HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pe32.th32ProcessID);	//第二个参数为0指示当前进程
		MODULEENTRY32 me32;
		memset(&me32,0,sizeof(MODULEENTRY32));
		me32.dwSize = sizeof(me32);
		Module32First(hModuleSnap,&me32);

		LV_ITEM vitem;
		//初始化
		memset(&vitem,0,sizeof(LV_ITEM));
		vitem.mask = LVIF_TEXT;
		vitem.cchTextMax = MAX_PATH;
		vitem.iItem = i;	//第0行

		vitem.iSubItem = 0;	//第0列
		vitem.pszText = (LPWSTR)pe32.szExeFile;	//进程名
		ListView_InsertItem(hListProcess,&vitem);	//插入一个新的项

		vitem.iSubItem = 1;	//第1列
		WCHAR szPIDBuffer[10] = {0};
		wsprintf(szPIDBuffer,L"%x",pe32.th32ProcessID);
		ListView_SetItemText(hListProcess,i,vitem.iSubItem,(LPWSTR)szPIDBuffer);	//为某一项的某一列插入文本
		//如果没有获取到模块信息或者如果PID等于0，就继续下一个进程
		if(hModuleSnap == INVALID_HANDLE_VALUE || pe32.th32ProcessID==0)
		{
			bMore = ::Process32Next(hProcessSnap,&pe32);
			i++;
			::CloseHandle(hModuleSnap);
			continue;
		}
		
		vitem.iSubItem = 2;	//第2列
		WCHAR ImageBase[10] = {0};
		wsprintf(ImageBase,L"%x",me32.modBaseAddr);
		ListView_SetItemText(hListProcess,i,vitem.iSubItem,(LPWSTR)ImageBase);	//为某一项的某一列插入文本

		vitem.iSubItem = 3;	//第3列
		WCHAR ImageSize[10] = {0};
		wsprintf(ImageSize,L"%x",me32.modBaseSize);
		ListView_SetItemText(hListProcess,i,vitem.iSubItem,(LPWSTR)ImageSize);	//为某一项的某一列插入文本

		bMore = ::Process32Next(hProcessSnap,&pe32);
		i++;
		::CloseHandle(hModuleSnap);
	}
	//不要忘记清除snapshot对象
	::CloseHandle(hProcessSnap);
}

void InitModulesListView(HWND hwndDlg){
	LV_COLUMN lv;
	HWND hListProcess;

	//初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	//获取IDC_LIST_MODOULE句柄
	hListProcess = GetDlgItem(hwndDlg,IDC_LIST_MODOULE);
	//设置整行选中
	SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,NULL);

	//第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("模块名称");	//列标题
	lv.cx = 100;	//列宽
	lv.iSubItem = 0;
	ListView_InsertColumn(hListProcess,0,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第二列
	lv.pszText = TEXT("模块路径");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess,1,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第三列
	lv.pszText = TEXT("模块基址");
	lv.cx = 100;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListProcess,2,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第四列
	lv.pszText = TEXT("模块大小");
	lv.cx = 100;
	lv.iSubItem = 3;
	//ListView_InsertColumn(hListProcess,3,&lv);
	SendMessage(hListProcess,LVM_INSERTCOLUMN,3,(DWORD)&lv);
}

void EnumProcessModule(HWND hListProcess,HWND hListModule,WPARAM wParam,LPARAM lParam){
	SendMessage(hListModule, LVM_DELETEALLITEMS, 0, 0);//删除所有行
	DWORD dwRowId;
	TCHAR szPid[0x20];
	LV_ITEM lv;

	//初始化
	memset(&lv,0,sizeof(LV_ITEM));
	memset(szPid,0,0x20);
	//获取选择行
	dwRowId = SendMessage(hListProcess,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
	if(dwRowId == -1){
		MessageBox(NULL,TEXT("请选择进程"),TEXT("出错啦"),MB_OK);
		return;
	}
	//获取PID
	lv.iSubItem = 1;		//要获取的列
	lv.pszText = szPid;		//指定存储查询结果的缓冲区
	lv.cchTextMax = 0x20;	//指定缓冲区的大小
	SendMessage(hListProcess,LVM_GETITEMTEXT,dwRowId,(DWORD)&lv);	//获取PID
	DWORD szPidNum;
	swscanf(szPid,L"%x",&szPidNum);
	dwPID = szPidNum;
	//如果PID为0，就不用显示
	if(szPidNum==0){
		return;
	}

	//根据PID的值调用API函数
	//获取进程的模块
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,szPidNum);	//第二个参数为0指示当前进程
	MODULEENTRY32 me32;
	memset(&me32,0,sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(me32);
	//将获取到的信息写入到List_View
	BOOL bMore = Module32First(hModuleSnap,&me32);
	for(int i=0;bMore;i++){
		LV_ITEM vitem;
		//初始化
		memset(&vitem,0,sizeof(LV_ITEM));
		vitem.mask = LVIF_TEXT;
		vitem.cchTextMax = MAX_PATH;
		vitem.iItem = i;	//第0行

		vitem.iSubItem = 0;	//第0列
		vitem.pszText = (LPWSTR)me32.szModule;	//模块名
		ListView_InsertItem(hListModule,&vitem);	//插入一个新的项

		vitem.iSubItem = 1;	//第1列
		WCHAR szModulePath[MAX_PATH] = {0};
		wsprintf(szModulePath,L"%s",me32.szExePath);
		ListView_SetItemText(hListModule,i,vitem.iSubItem,(LPWSTR)szModulePath);	//为某一项的某一列插入文本

		vitem.iSubItem = 2;	//第2列
		WCHAR szModuleBase[10] = {0};
		wsprintf(szModuleBase,L"%x",me32.modBaseAddr);
		ListView_SetItemText(hListModule,i,vitem.iSubItem,(LPWSTR)szModuleBase);	//为某一项的某一列插入文本

		vitem.iSubItem = 3;	//第3列
		WCHAR szModuleSize[10] = {0};
		wsprintf(szModuleSize,L"%x",me32.modBaseSize);
		ListView_SetItemText(hListModule,i,vitem.iSubItem,(LPWSTR)szModuleSize);	//为某一项的某一列插入文本

		bMore = Module32Next(hModuleSnap,&me32);
	}
	::CloseHandle(hModuleSnap);
}

void InitSectionListView(HWND hwndDlg){
	LV_COLUMN lv;
	HWND hSectionDlg;

	//初始化
	memset(&lv,0,sizeof(LV_COLUMN));
	//获取IDC_LIST_PROCESS句柄
	hSectionDlg = GetDlgItem(hwndDlg,IDC_LIST_SectionView);
	//设置整行选中
	//SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,NULL);
	ListView_SetExtendedListViewStyle(hSectionDlg,LVS_EX_FULLROWSELECT);

	//第一列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("节名");	//列标题
	lv.cx = 100;	//列宽
	lv.iSubItem = 0;
	//ListView_InsertColumn(hListProcess,0,&lv);
	SendMessage(hSectionDlg,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第二列
	lv.pszText = TEXT("文件偏移");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hSectionDlg,1,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第三列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("文件大小");	//列标题
	lv.cx = 100;	//列宽
	lv.iSubItem = 2;
	ListView_InsertColumn(hSectionDlg,2,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第四列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("内存偏移");	//列标题
	lv.cx = 100;	//列宽
	lv.iSubItem = 3;
	ListView_InsertColumn(hSectionDlg,3,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//第五列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("内存大小");	//列标题
	lv.cx = 100;	//列宽
	lv.iSubItem = 4;
	ListView_InsertColumn(hSectionDlg,4,&lv);
	//第四列
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("节区属性");	//列标题
	lv.cx = 100;	//列宽
	lv.iSubItem = 5;
	ListView_InsertColumn(hSectionDlg,5,&lv);

	getSectionInfo(hSectionDlg);
}

void getSectionInfo(HWND hSectionDlg){
	LV_ITEMA vitem;

	//初始化
	memset(&vitem,0,sizeof(LV_ITEMA));
	vitem.mask = LVIF_TEXT;

	//将节中的信息填入到Dlg中
	for(int i=0;i<PE.PEHeader_p->NumberOfSections;i++,PE.sectionHeader_p++){
		vitem.pszText = PE.sectionHeader_p->Name;
		vitem.iItem = i;
		vitem.iSubItem = 0;
		//SendMessageA(hSectionDlg,LVM_INSERTITEMA,0,(DWORD)&vitem);
		//第N行的第一列用LVM_INSERTITEM，不是第一列的用LVM_SETITEMA
		SendMessageA(hSectionDlg,LVM_INSERTITEMA,0,(DWORD)&vitem);

		char szBuffer[30];
		sprintf(szBuffer,"%x\n",PE.sectionHeader_p->PointerToRawData);
		vitem.pszText = szBuffer;
		vitem.iItem = i;
		vitem.iSubItem = 1;
		//ListView_SetItem(hSectionDlg,&vitem);
		SendMessageA(hSectionDlg,LVM_SETITEMA,0,(DWORD)&vitem);

		sprintf(szBuffer,"%x\n",PE.sectionHeader_p->SizeOfRawData);
		vitem.pszText = szBuffer;
		vitem.iItem = i;
		vitem.iSubItem = 2;
		//ListView_SetItem(hSectionDlg,&vitem);
		SendMessageA(hSectionDlg,LVM_SETITEMA,0,(DWORD)&vitem);

		sprintf(szBuffer,"%x\n",PE.sectionHeader_p->VirtualAddress);
		vitem.pszText = szBuffer;
		vitem.iItem = i;
		vitem.iSubItem = 3;
		//ListView_SetItem(hSectionDlg,&vitem);
		SendMessageA(hSectionDlg,LVM_SETITEMA,0,(DWORD)&vitem);


		sprintf(szBuffer,"%x\n",PE.sectionHeader_p->Misc);
		vitem.pszText = szBuffer;
		vitem.iItem = i;
		vitem.iSubItem = 4;
		//ListView_SetItem(hSectionDlg,&vitem);
		SendMessageA(hSectionDlg,LVM_SETITEMA,0,(DWORD)&vitem);

		sprintf(szBuffer,"%x\n",PE.sectionHeader_p->Characteristics);
		vitem.pszText = szBuffer;
		vitem.iItem = i;
		vitem.iSubItem = 5;
		//ListView_SetItem(hSectionDlg,&vitem);
		SendMessageA(hSectionDlg,LVM_SETITEMA,0,(DWORD)&vitem);
	}
}

void InitDirectionView(HWND hwndDlg){
	TCHAR szBuffer[30] = {0};

	//设置RVA
	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[0].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_exportRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[1].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_importRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[2].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_resourceRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[3].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_abnormalRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[4].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_safeRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[5].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_relocationRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[6].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_debugRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[7].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_versionRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[8].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_gobalPointRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[9].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TlsRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[10].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_deriveExportRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[11].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_bindRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[12].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_IATRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[13].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_delayRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[14].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_COMRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[15].VirtualAddress);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_reserveRVA,WM_SETTEXT,0,(DWORD)szBuffer);

	//设置SIZE

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[0].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_exportSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[1].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_importSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[2].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_resourceSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[3].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_abnormalSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[4].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_safeSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[5].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_relocationSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[6].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_debugSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[7].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_versionSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[8].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_gobalPointSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[9].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_TlsSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[10].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_deriveExportSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[11].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_bindSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[12].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_IATSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[13].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_delaySIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[14].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_COMSIZE,WM_SETTEXT,0,(DWORD)szBuffer);

	wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->DataDirectory[15].Size);
	SendDlgItemMessage(hwndDlg,IDC_EDIT_reservaSIZE,WM_SETTEXT,0,(DWORD)szBuffer);
}