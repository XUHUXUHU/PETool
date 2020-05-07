// PETool.cpp : ����Ӧ�ó������ڵ㡣
//

#include "stdafx.h"
#include "PETool.h"

//��������Ϣ������
INT_PTR CALLBACK MainDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
);
//PE�鿴����Ϣ������
INT_PTR CALLBACK messgeCheckDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
);
//PE�鿴���Ľ���Ϣ������
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

HINSTANCE hAppInstance;	//�洢ȫ�ֳ�����
char FileName[256];		//�洢�����ļ�ʱ��ѡ����ļ���
struct wholePE PE;		//�洢�������ļ�ʱPE�ļ����������PE�ṹ
char* fileBuffer_p;		//�洢�������ļ�ʱ��ѡ�е�PE�ļ���fileBuffer
char* pImageBuffer;	//�洢�����ļ�ʱ��ѡ�е�PE�ļ���pImageBufer
char detailBuffer[DetailBufferSize];	//�洢�������ļ�ʱ��ϸ��Ϣ�е���Ϣ
char* ShellPath = "F:\\VSC++\\PETool\\Debug\\shell4.exe";
//char FileNameOfShell[256];	//�洢����ӿ�ʱ��ѡ����ļ���
DWORD dwPID = -1;	//��ѡ���е�PID

int APIENTRY _tWinMain(HINSTANCE hInstance,
                     HINSTANCE hPrevInstance,
                     LPTSTR    lpCmdLine,
                     int       nCmdShow)
{
	hAppInstance = hInstance;
	
	//��������Ҫ���ص�ͨ�ÿؼ�����
	INITCOMMONCONTROLSEX icex;
	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES;
	InitCommonControlsEx(&icex);

	//���Ի��򴴽�����
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
			//�رնԻ���
			EndDialog(hwndDlg,0);
			break;
		}
	case WM_INITDIALOG:
		{
			/*
			//����ͼ��
			HICON hIcon = LoadIcon(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_MAIN));
			//����ͼ��
			SendMessage(hwndDlg,WM_SETICON,ICON_BIG,(long)hIcon);
			SendMessage(hwndDlg,WM_SETICON,ICON_SMALL,(long)hIcon);
			*/
			//����ProcessListView�ķ��
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
		//PE�鿴��
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
					//���µĶԻ���
					DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_messgeCheck),hwndDlg,messgeCheckDlgProc);
				}

				return TRUE;
			}
		//����ӿ�
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
		//dllע��
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
						MessageBoxA(NULL,"ע��ɹ�","",MB_OK);
					}else{
						MessageBoxA(NULL,"ע��ʧ��","",MB_OK);
					}
				}
				return TRUE;
			}
		case IDC_BUTTON_Update:
			{
				EnumProcess(GetDlgItem(hwndDlg,IDC_LIST_PROCESS));	//����ProcessListView�е�����
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

//PE��Ϣ�鿴��Ϣ������
INT_PTR CALLBACK messgeCheckDlgProc(
  HWND hwndDlg,  // handle to dialog box
  UINT uMsg,     // message
  WPARAM wParam, // first message parameter
  LPARAM lParam  // second message parameter
){
	switch(uMsg){
	case WM_CLOSE:
		{
			//�رնԻ���
			EndDialog(hwndDlg,0);
			break;
		}
	case WM_INITDIALOG:
		{
			//��PE�ļ� ��ȡ�����Ϣ
			//TCHAR szBuffer[128];
			//wsprintf(szBuffer,TEXT("%x\n"),"00418347");
			//SendDlgItemMessage(hwndDlg,IDC_EDIT_rukou,WM_SETTEXT,0,(DWORD)szBuffer);
			int fileBufferSize;
			fileBuffer_p = getFileContent(FileName,&fileBufferSize);
			analyzePE(fileBuffer_p,&PE);
			pImageBuffer = fileBufferToImageBuffer(fileBuffer_p,&fileBufferSize,&PE);

			TCHAR szBuffer[128];
			//��ڵ�
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->AddressOfEntryPoint);
			//SendDlgItemMessage(hwndDlg,IDC_EDIT_rukou,WM_SETTEXT,0,szBuffer);
			SetWindowText(GetDlgItem(hwndDlg,IDC_EDIT_rukou),szBuffer);

			//�����ַ
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->ImageBase);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_imageBase,WM_SETTEXT,0,(DWORD)szBuffer);

			//�����С
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->SizeOfImage);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_imageSize,WM_SETTEXT,0,(DWORD)szBuffer);

			//�����ַ
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->BaseOfCode);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_codeBase,WM_SETTEXT,0,(DWORD)szBuffer);

			//���ݻ���
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->BaseOfData);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_dataBase,WM_SETTEXT,0,(DWORD)szBuffer);

			//�ڴ����
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->SectionAlignment);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_memoAlign,WM_SETTEXT,0,(DWORD)szBuffer);

			//�ļ�����
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->FileAlignment);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_fileAlign,WM_SETTEXT,0,(DWORD)szBuffer);

			//��־��
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->Magic);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_flagWord,WM_SETTEXT,0,(DWORD)szBuffer);

			//��ϵͳ
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->Subsystem);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_childSys,WM_SETTEXT,0,(DWORD)szBuffer);

			//������Ŀ
			wsprintf(szBuffer,TEXT("%x\n"),PE.PEHeader_p->NumberOfSections);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_quduanNum,WM_SETTEXT,0,(DWORD)szBuffer);

			//ʱ���
			wsprintf(szBuffer,TEXT("%x\n"),PE.PEHeader_p->TimeDateStamp);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_timeNode,WM_SETTEXT,0,(DWORD)szBuffer);

			//PEͷ��С
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->SizeOfHeaders);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_PEHeaderSize,WM_SETTEXT,0,(DWORD)szBuffer);

			//����ֵ
			wsprintf(szBuffer,TEXT("%x\n"),PE.PEHeader_p->Characteristics);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_tezhengNum,WM_SETTEXT,0,(DWORD)szBuffer);

			//У���
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->CheckSum);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_sum,WM_SETTEXT,0,(DWORD)szBuffer);

			//��ѡPEͷ
			wsprintf(szBuffer,TEXT("%x\n"),PE.PEHeader_p->SizeOfOptionalHeader);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_optionPE,WM_SETTEXT,0,(DWORD)szBuffer);

			//Ŀ¼����Ŀ
			wsprintf(szBuffer,TEXT("%x\n"),PE.optionPEHeader_p->NumberOfRvaAndSizes);
			SendDlgItemMessage(hwndDlg,IDC_EDIT_muluNum,WM_SETTEXT,0,(DWORD)szBuffer);

			break;
		}
	case WM_COMMAND:
		{
		switch(LOWORD(wParam))
		{
		//PE�鿴��
		case IDC_BUTTON_close:
			{
				EndDialog(hwndDlg,0);
				return TRUE;
			}
		case IDC_BUTTON_quduan:
			{
				//����
				//���µĶԻ���
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_SetionDIALOG),hwndDlg,SectionDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_mulu:
			{
				//Ŀ¼
				//���µĶԻ���
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
			//�رնԻ���
			EndDialog(hwndDlg,0);
			break;
		}
	case WM_INITDIALOG:
		{
			//��ʼ���ڱ��List View
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
			//�رնԻ���
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
		//PE�鿴��
		case IDC_BUTTON_DirectoryClose:
			{
				EndDialog(hwndDlg,0);
				return TRUE;
			}
		case IDC_BUTTON_derectory_exportDetail:
			{
				//������ϸ��Ϣ���е���Ϣ
				getExportDirectory(detailBuffer,4096,pImageBuffer);
				//���µĶԻ���
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_directory_importDetail:
			{
				//���µĶԻ���
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_directory_resourceDetail:
			{
				//���µĶԻ���
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_directory_relocationDetail:
			{
				//���µĶԻ���
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_directory_bindDetail:
			{
				//���µĶԻ���
				DialogBox(hAppInstance,MAKEINTRESOURCE(IDD_DIALOG_PE_detail),hwndDlg,detailDlgProc);
				return TRUE;
			}
		case IDC_BUTTON_directory_IATDetail:
			{
				//���µĶԻ���
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
			//�رնԻ���
			EndDialog(hwndDlg,0);
			break;
		}
	case WM_INITDIALOG:
		{
			
			//SetWindowLong(hwndDlg,0,ES_MULTILINE);
			//SetWindowLong(hwndDlg,IDC_EDIT_PE_detail,ES_WANTRETURN);
			SetDlgItemTextA(hwndDlg,IDC_EDIT_PE_detail,detailBuffer);	//��edit control��\r\n��ʾ����
			//����detailInfoָ�������
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

	//��ʼ��
	memset(&lv,0,sizeof(LV_COLUMN));
	//��ȡIDC_LIST_PROCESS���
	hListProcess = GetDlgItem(hwndDlg,IDC_LIST_PROCESS);
	//��������ѡ��
	//SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,NULL);
	ListView_SetExtendedListViewStyle(hListProcess,LVS_EX_FULLROWSELECT);

	//��һ��
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("����");	//�б���
	lv.cx = 100;	//�п�
	lv.iSubItem = 0;
	//ListView_InsertColumn(hListProcess,0,&lv);
	SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//�ڶ���
	lv.pszText = TEXT("PID");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess,1,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//������
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("�����ַ");	//�б���
	lv.cx = 100;	//�п�
	lv.iSubItem = 2;	//��������
	ListView_InsertColumn(hListProcess,2,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//������
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("�����С");	//�б���
	lv.cx = 100;	//�п�
	lv.iSubItem = 3;
	ListView_InsertColumn(hListProcess,3,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);

	EnumProcess(hListProcess);
}

void EnumProcess(HWND hListProcess){
	SendMessage(hListProcess, LVM_DELETEALLITEMS, 0, 0);//ɾ��������
	//����API ���ϵͳ�еĽ�����Ϣ
	PROCESSENTRY32 pe32;
	memset(&pe32,0,sizeof(PROCESSENTRY32));
	//��ʹ������ṹ֮ǰ�����������Ĵ�С
	pe32.dwSize = sizeof(pe32);
	//��ϵͳ�����еĽ�����һ������
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot����ʧ��\n");
		return;
	}
	//�������̿��գ�������ʾÿ�����̵���Ϣ
	BOOL bMore = ::Process32First(hProcessSnap,&pe32);
	int i=0;
	while(bMore)
	{
		//��ȡ���̵�ģ��
		HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,pe32.th32ProcessID);	//�ڶ�������Ϊ0ָʾ��ǰ����
		MODULEENTRY32 me32;
		memset(&me32,0,sizeof(MODULEENTRY32));
		me32.dwSize = sizeof(me32);
		Module32First(hModuleSnap,&me32);

		LV_ITEM vitem;
		//��ʼ��
		memset(&vitem,0,sizeof(LV_ITEM));
		vitem.mask = LVIF_TEXT;
		vitem.cchTextMax = MAX_PATH;
		vitem.iItem = i;	//��0��

		vitem.iSubItem = 0;	//��0��
		vitem.pszText = (LPWSTR)pe32.szExeFile;	//������
		ListView_InsertItem(hListProcess,&vitem);	//����һ���µ���

		vitem.iSubItem = 1;	//��1��
		WCHAR szPIDBuffer[10] = {0};
		wsprintf(szPIDBuffer,L"%x",pe32.th32ProcessID);
		ListView_SetItemText(hListProcess,i,vitem.iSubItem,(LPWSTR)szPIDBuffer);	//Ϊĳһ���ĳһ�в����ı�
		//���û�л�ȡ��ģ����Ϣ�������PID����0���ͼ�����һ������
		if(hModuleSnap == INVALID_HANDLE_VALUE || pe32.th32ProcessID==0)
		{
			bMore = ::Process32Next(hProcessSnap,&pe32);
			i++;
			::CloseHandle(hModuleSnap);
			continue;
		}
		
		vitem.iSubItem = 2;	//��2��
		WCHAR ImageBase[10] = {0};
		wsprintf(ImageBase,L"%x",me32.modBaseAddr);
		ListView_SetItemText(hListProcess,i,vitem.iSubItem,(LPWSTR)ImageBase);	//Ϊĳһ���ĳһ�в����ı�

		vitem.iSubItem = 3;	//��3��
		WCHAR ImageSize[10] = {0};
		wsprintf(ImageSize,L"%x",me32.modBaseSize);
		ListView_SetItemText(hListProcess,i,vitem.iSubItem,(LPWSTR)ImageSize);	//Ϊĳһ���ĳһ�в����ı�

		bMore = ::Process32Next(hProcessSnap,&pe32);
		i++;
		::CloseHandle(hModuleSnap);
	}
	//��Ҫ�������snapshot����
	::CloseHandle(hProcessSnap);
}

void InitModulesListView(HWND hwndDlg){
	LV_COLUMN lv;
	HWND hListProcess;

	//��ʼ��
	memset(&lv,0,sizeof(LV_COLUMN));
	//��ȡIDC_LIST_MODOULE���
	hListProcess = GetDlgItem(hwndDlg,IDC_LIST_MODOULE);
	//��������ѡ��
	SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,NULL);

	//��һ��
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("ģ������");	//�б���
	lv.cx = 100;	//�п�
	lv.iSubItem = 0;
	ListView_InsertColumn(hListProcess,0,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//�ڶ���
	lv.pszText = TEXT("ģ��·��");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hListProcess,1,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//������
	lv.pszText = TEXT("ģ���ַ");
	lv.cx = 100;
	lv.iSubItem = 2;
	ListView_InsertColumn(hListProcess,2,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//������
	lv.pszText = TEXT("ģ���С");
	lv.cx = 100;
	lv.iSubItem = 3;
	//ListView_InsertColumn(hListProcess,3,&lv);
	SendMessage(hListProcess,LVM_INSERTCOLUMN,3,(DWORD)&lv);
}

void EnumProcessModule(HWND hListProcess,HWND hListModule,WPARAM wParam,LPARAM lParam){
	SendMessage(hListModule, LVM_DELETEALLITEMS, 0, 0);//ɾ��������
	DWORD dwRowId;
	TCHAR szPid[0x20];
	LV_ITEM lv;

	//��ʼ��
	memset(&lv,0,sizeof(LV_ITEM));
	memset(szPid,0,0x20);
	//��ȡѡ����
	dwRowId = SendMessage(hListProcess,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
	if(dwRowId == -1){
		MessageBox(NULL,TEXT("��ѡ�����"),TEXT("������"),MB_OK);
		return;
	}
	//��ȡPID
	lv.iSubItem = 1;		//Ҫ��ȡ����
	lv.pszText = szPid;		//ָ���洢��ѯ����Ļ�����
	lv.cchTextMax = 0x20;	//ָ���������Ĵ�С
	SendMessage(hListProcess,LVM_GETITEMTEXT,dwRowId,(DWORD)&lv);	//��ȡPID
	DWORD szPidNum;
	swscanf(szPid,L"%x",&szPidNum);
	dwPID = szPidNum;
	//���PIDΪ0���Ͳ�����ʾ
	if(szPidNum==0){
		return;
	}

	//����PID��ֵ����API����
	//��ȡ���̵�ģ��
	HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,szPidNum);	//�ڶ�������Ϊ0ָʾ��ǰ����
	MODULEENTRY32 me32;
	memset(&me32,0,sizeof(MODULEENTRY32));
	me32.dwSize = sizeof(me32);
	//����ȡ������Ϣд�뵽List_View
	BOOL bMore = Module32First(hModuleSnap,&me32);
	for(int i=0;bMore;i++){
		LV_ITEM vitem;
		//��ʼ��
		memset(&vitem,0,sizeof(LV_ITEM));
		vitem.mask = LVIF_TEXT;
		vitem.cchTextMax = MAX_PATH;
		vitem.iItem = i;	//��0��

		vitem.iSubItem = 0;	//��0��
		vitem.pszText = (LPWSTR)me32.szModule;	//ģ����
		ListView_InsertItem(hListModule,&vitem);	//����һ���µ���

		vitem.iSubItem = 1;	//��1��
		WCHAR szModulePath[MAX_PATH] = {0};
		wsprintf(szModulePath,L"%s",me32.szExePath);
		ListView_SetItemText(hListModule,i,vitem.iSubItem,(LPWSTR)szModulePath);	//Ϊĳһ���ĳһ�в����ı�

		vitem.iSubItem = 2;	//��2��
		WCHAR szModuleBase[10] = {0};
		wsprintf(szModuleBase,L"%x",me32.modBaseAddr);
		ListView_SetItemText(hListModule,i,vitem.iSubItem,(LPWSTR)szModuleBase);	//Ϊĳһ���ĳһ�в����ı�

		vitem.iSubItem = 3;	//��3��
		WCHAR szModuleSize[10] = {0};
		wsprintf(szModuleSize,L"%x",me32.modBaseSize);
		ListView_SetItemText(hListModule,i,vitem.iSubItem,(LPWSTR)szModuleSize);	//Ϊĳһ���ĳһ�в����ı�

		bMore = Module32Next(hModuleSnap,&me32);
	}
	::CloseHandle(hModuleSnap);
}

void InitSectionListView(HWND hwndDlg){
	LV_COLUMN lv;
	HWND hSectionDlg;

	//��ʼ��
	memset(&lv,0,sizeof(LV_COLUMN));
	//��ȡIDC_LIST_PROCESS���
	hSectionDlg = GetDlgItem(hwndDlg,IDC_LIST_SectionView);
	//��������ѡ��
	//SendMessage(hListProcess,LVM_SETEXTENDEDLISTVIEWSTYLE,LVS_EX_FULLROWSELECT,NULL);
	ListView_SetExtendedListViewStyle(hSectionDlg,LVS_EX_FULLROWSELECT);

	//��һ��
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("����");	//�б���
	lv.cx = 100;	//�п�
	lv.iSubItem = 0;
	//ListView_InsertColumn(hListProcess,0,&lv);
	SendMessage(hSectionDlg,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//�ڶ���
	lv.pszText = TEXT("�ļ�ƫ��");
	lv.cx = 100;
	lv.iSubItem = 1;
	ListView_InsertColumn(hSectionDlg,1,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//������
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("�ļ���С");	//�б���
	lv.cx = 100;	//�п�
	lv.iSubItem = 2;
	ListView_InsertColumn(hSectionDlg,2,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//������
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("�ڴ�ƫ��");	//�б���
	lv.cx = 100;	//�п�
	lv.iSubItem = 3;
	ListView_InsertColumn(hSectionDlg,3,&lv);
	//SendMessage(hListProcess,LVM_INSERTCOLUMN,0,(DWORD)&lv);
	//������
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("�ڴ��С");	//�б���
	lv.cx = 100;	//�п�
	lv.iSubItem = 4;
	ListView_InsertColumn(hSectionDlg,4,&lv);
	//������
	lv.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
	lv.pszText = TEXT("��������");	//�б���
	lv.cx = 100;	//�п�
	lv.iSubItem = 5;
	ListView_InsertColumn(hSectionDlg,5,&lv);

	getSectionInfo(hSectionDlg);
}

void getSectionInfo(HWND hSectionDlg){
	LV_ITEMA vitem;

	//��ʼ��
	memset(&vitem,0,sizeof(LV_ITEMA));
	vitem.mask = LVIF_TEXT;

	//�����е���Ϣ���뵽Dlg��
	for(int i=0;i<PE.PEHeader_p->NumberOfSections;i++,PE.sectionHeader_p++){
		vitem.pszText = PE.sectionHeader_p->Name;
		vitem.iItem = i;
		vitem.iSubItem = 0;
		//SendMessageA(hSectionDlg,LVM_INSERTITEMA,0,(DWORD)&vitem);
		//��N�еĵ�һ����LVM_INSERTITEM�����ǵ�һ�е���LVM_SETITEMA
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

	//����RVA
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

	//����SIZE

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