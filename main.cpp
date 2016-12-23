#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <winbase.h>
#include "resource.h"
typedef struct {
    char *pName;
    char *pSig;
    char *pToolTip;
    }SigTable;
long total;

HINSTANCE hInst;
char SigBytes[512];

// Function Prototype
BOOL CALLBACK DialogProc(HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam);
int RvaToOffset(IMAGE_NT_HEADERS *NT, int Rva);
void GetPEInformation(HWND hWin,char *FilePath);
SigTable *Fill_SigTable_From_File_And_Comapre_it(HWND hWin,SigTable *table);
BOOL CompareSig(char *SigFile,char *SigBD,int lenBD);

// Function Syntaxe

void GetPEInformation(HWND hWin,char *FilePath)
{
	HANDLE hFile;
	HANDLE oFile;
	unsigned char *mFile;
	int sFile;
    IMAGE_NT_HEADERS32 *NT_Header;
    PIMAGE_SECTION_HEADER section;
	int EntryPoint;
	int offsetOEP;
	char buffer[512];
	int i,j;

    hFile=CreateFile(FilePath,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
    sFile=GetFileSize(hFile,0);
    oFile=CreateFileMapping(hFile,0,PAGE_READONLY,0,0,0);
    mFile=(unsigned char *)MapViewOfFile(oFile,FILE_MAP_READ,0,0,0);
    NT_Header=(IMAGE_NT_HEADERS32*)(mFile+ ((IMAGE_DOS_HEADER*)(mFile))->e_lfanew);
    EntryPoint = NT_Header->OptionalHeader.AddressOfEntryPoint;
    offsetOEP=RvaToOffset(NT_Header,EntryPoint);
    wsprintf(buffer,"%.8X",EntryPoint);
    SetDlgItemText(hWin,ID_EntryPoint,buffer);
    wsprintf(buffer,"%.8X",NT_Header->OptionalHeader.ImageBase);
    SetDlgItemText(hWin,ID_ImageBase,buffer);
    section = IMAGE_FIRST_SECTION (NT_Header);
    SetDlgItemText(hWin,ID_EPSection,(char *)section->Name);
    j=0;
    for(i=0;i<4;i++)
    {
        if(i!=3)
        {
            wsprintf(&buffer[i+j],"%.2X,",*(mFile+offsetOEP+i));
            j=j+2;
        }
        else
        {
            wsprintf(&buffer[i+j],"%.2X",*(mFile+offsetOEP+i));
        }
    }
    SetDlgItemText(hWin,ID_FirstBytes,buffer);

    //=====================Get 256 FirstBytes From OEP================!
    j=0;
    for(i=0;i<250;i++)
    {
        wsprintf(&SigBytes[i+j],"%.2X",*(mFile+offsetOEP+i));
        j=j+1;
    }
    //=====================Get 512 FirstBytes From OEP=================!

    UnmapViewOfFile(mFile);
    CloseHandle(oFile);
    CloseHandle(hFile);
    }



SigTable *Fill_SigTable_From_File_And_Comapre_it(HWND hWin,SigTable *table)
{
    HANDLE hFile;
	HANDLE oFile;
	unsigned char *mFile;
	int sFile;
	int i,j,M,N,x;
	int SigSize[3][3];
	char temp[20];
	char PathSigFile[512];
	BOOL start;
                        for(i=GetModuleFileName(hInst,PathSigFile,sizeof(PathSigFile));PathSigFile[i]!='\\';i--)
                        {
                            PathSigFile[i]=0x00;
                        }
                        lstrcat(PathSigFile,"SigBD.txt");
                        hFile=CreateFile(PathSigFile,GENERIC_READ,FILE_SHARE_READ,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
                        sFile=GetFileSize(hFile,0);
                        oFile=CreateFileMapping(hFile,0,PAGE_READONLY,0,0,0);
                        mFile=(unsigned char *)MapViewOfFile(oFile,FILE_MAP_READ,0,0,0);
                        i=j=M=N=0;
                        while((char)*(mFile+i)!='\n')
                        {
                            temp[i]=(char)*(mFile+i);
                            i++;
                        }
                        sscanf(temp,"[%ld]",&total);
                        table=(SigTable *)malloc(3*total*sizeof(SigTable));
                        memset(temp,0x00,20);
                        while(((char)*(mFile+i)!='\0') && (N<total))
                        {
                            switch((char)*(mFile+i))
                            {
                                case '[':
                                start=TRUE;
                                break;
                                case ']':
                                start=FALSE;
                                temp[j]='\0';
                                x=i+11;
                                sscanf(temp,"%d,%d,%d",&SigSize[M][N],&SigSize[M+1][N],&SigSize[M+2][N]);
                                table[N].pName=(char *)malloc(SigSize[M][N]);
                                table[N].pSig=(char *)malloc(SigSize[M+1][N]);
                                table[N].pToolTip=(char *)malloc(SigSize[M+2][N]);
                                lstrcpyn(table[N].pName,(char *)(mFile+x),SigSize[M][N]+1);
                                x=x+SigSize[M][N]+9;
                                lstrcpyn(table[N].pSig,(char *)(mFile+x),SigSize[M+1][N]+1);
                                x=x+SigSize[M+1][N]+13;
                                lstrcpyn(table[N].pToolTip,(char *)(mFile+x),SigSize[M+2][N]+1);

                                if(CompareSig(SigBytes,table[N].pSig,SigSize[M+1][N]))
                                {
                                    SetDlgItemText(hWin,ID_SIG,table[N].pName);
                                    SetDlgItemText(hWin,ID_ToolTip,table[N].pToolTip);
                                    goto leave;
                                }
                                memset(temp,0x00,20);
                                N++;
                                j=0;
                                break;
                                default:
                                if(start)
                                {
                                temp[j]=(char)*(mFile+i);
                                j++;
                                }
                            }
                        i++;
                        }
                        SetDlgItemText(hWin,ID_SIG,"Not Found");
                        leave:
                        UnmapViewOfFile(mFile);
                        CloseHandle(oFile);
                        CloseHandle(hFile);
                        return table;
}
BOOL CompareSig(char *SigFile,char *SigBD,int lenBD)
{
int i;

for(i=0;i<lenBD;i++)
    {
        if(SigBD[i]!='?')
        {
            if (SigBD[i]!=SigFile[i])
            {
                return FALSE;
            }
        }
    }
    return TRUE;

}



int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
    hInst = hInstance;
    return DialogBox(hInstance, MAKEINTRESOURCE(DLG_MAIN), NULL, DialogProc);
}

BOOL CALLBACK DialogProc(HWND hWin, UINT uMsg, WPARAM wParam, LPARAM lParam)
{


	OPENFILENAME ofn;
	char buffer[512];
	SigTable *table;
	int i;
    switch(uMsg)
    {
        case WM_INITDIALOG:

        return TRUE;

        case WM_CLOSE:
            EndDialog(hWin, 0);
        return TRUE;

        case WM_COMMAND:
            switch(LOWORD(wParam))
            {

                case IDOK:
                    ZeroMemory(&ofn, sizeof(ofn));
                    ZeroMemory(buffer, sizeof(buffer));
                    ofn.lStructSize = sizeof(ofn);
                    ofn.lpstrFilter = "Win32\0*.exe";
                    ofn.lpstrFile=buffer;
                    ofn.nMaxFile = 256;
                    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
                    if (GetOpenFileName(&ofn))
                    {
                        SetDlgItemText(hWin,ID_File,buffer);
                        GetPEInformation(hWin,buffer);
                        table=Fill_SigTable_From_File_And_Comapre_it(hWin,table);
                        for(i=0;i<total ;i++)
                        {
                            free(table[i].pName);
                            free(table[i].pSig);
                            free(table[i].pToolTip);
                        }
                        free(table);
                    }
                break;
            }
    }
    return FALSE;
}


int RvaToOffset(IMAGE_NT_HEADERS *NT, int Rva)
{
    DWORD Offset = Rva, Limit;
    IMAGE_SECTION_HEADER *Img;
    WORD i;
    Img = IMAGE_FIRST_SECTION(NT);
    if (Rva < Img->PointerToRawData)
        return Rva;
    for (i = 0; i < NT->FileHeader.NumberOfSections; i++)
    {
        if (Img[i].SizeOfRawData)
            Limit = Img[i].SizeOfRawData;
        else
            Limit = Img[i].Misc.VirtualSize;

        if (Rva >= Img[i].VirtualAddress &&
            Rva < (Img[i].VirtualAddress + Limit))
        {
            if (Img[i].PointerToRawData != 0)
            {
                Offset -= Img[i].VirtualAddress;
                Offset += Img[i].PointerToRawData;
            }
            return Offset;
        }
    }
    return 0;
}
