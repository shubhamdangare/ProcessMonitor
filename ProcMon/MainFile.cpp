#include<windows.h>
#include<tlhelp32.h>
#include<stdio.h>
#include<iostream>
#include<sys/stat.h>
#include<sys/types.h>
#include<io.h>
#include <psapi.h>
#define PSAPI_VERSION 1
#pragma comment(lib, "psapi.lib")

using namespace std;


typedef struct LogFile{


	char ProcessName[50];
	unsigned int pid;
	unsigned int ppid;
	unsigned int thread_cnt;
}LOGFILE;

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class ThreadInfo{

	private:
		DWORD PID;
		HANDLE hThreadSnap;
		THREADENTRY32 te32;  //Describes an entry from a list of the threads executing in the system when a snapshot was taken.

								/*

								typedef struct tagTHREADENTRY32 {
									 DWORD dwSize;  =>The size of the structure, in bytes. Before calling the Thread32First function, set this member to sizeof(THREADENTRY32). If you do not initialize dwSize, Thread32First fails.
									 DWORD cntUsage; =>This member is no longer used and is always set to zero.
									 DWORD th32ThreadID; =>The thread identifier, compatible with the thread identifier returned by the CreateProcess function
									DWORD th32OwnerProcessID;  =>The identifier of the process that created the thread.
									 LONG  tpBasePri;   =>The kernel base priority level assigned to the thread. The priority is a number from 0 to 31, with 0 representing the lowest possible thread priority. For more information, see KeQueryPriorityThread
									 LONG  tpDeltaPri;  =>This member is no longer used and is always set to zero
									 DWORD dwFlags;  =>This member is no longer used and is always set to zero
									} THREADENTRY32, *PTHREADENTRY32;



								*/
	public:
		ThreadInfo(DWORD);
		BOOL ThreadDisplay();
};

ThreadInfo::ThreadInfo(DWORD no){
	PID = no;
	hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,PID);  /* Takes a snapshot of the specified processes, as well as the heaps, modules, and threads used by these processes.

																		HANDLE WINAPI CreateToolhelp32Snapshot(
																				_In_ DWORD dwFlags,
																				_In_ DWORD th32ProcessID
																			);
																		
																	*/
																		
	if(hThreadSnap == INVALID_HANDLE_VALUE){
		cout<<"Uaable to create the snapshot of current thread pool"<<endl;
		return;
	}
	te32.dwSize = sizeof(THREADENTRY32);
}

BOOL ThreadInfo::ThreadDisplay(){
	if(!Thread32First(hThreadSnap,&te32)){
											//Retrieves information about the first thread of any process encountered in a system snapshot. #define CALLBACK __stdcall
											/* 
															BOOL WINAPI Thread32First(
															 _In_    HANDLE          hSnapshot, =>A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
															_Inout_ LPTHREADENTRY32 lpte =>A pointer to a THREADENTRY32 structure.	
															);


											*/

		cout<<"Error :in Getting the first Thread"<<endl;
		CloseHandle(hThreadSnap);
						/*	Closes an open object handle.
						 BOOL WINAPI CloseHandle(
						_In_ HANDLE hObject  =>A valid handle to an open object.
							);
						*/
		return FALSE;
	}
	cout<<"Thread of this Process:"<<endl;

	do{
		if(te32.th32OwnerProcessID == PID){
			cout<<"\t THREAD ID :"<<te32.th32ThreadID<<endl;
		}
	}while(Thread32Next	(hThreadSnap,&te32)); // Retrieves information about the next thread of any process encountered in the system memory snapshot.
	CloseHandle(hThreadSnap);
	return TRUE;
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
class DLLInfo{

	private:
		DWORD PID;
		MODULEENTRY32 me32;
							/*	Describes an entry from a list of the modules belonging to the specified process.
							typedef struct tagMODULEENTRY32 {
								DWORD   dwSize;  =>The size of the structure, in bytes. Before calling the Module32First function, set this member to sizeof(MODULEENTRY32). If you do not initialize dwSize, Module32First fails.
								DWORD   th32ModuleID; =>This member is no longer used, and is always set to one.
								DWORD   th32ProcessID; =>The identifier of the process whose modules are to be examined.
								DWORD   GlblcntUsage;  =>The load count of the module, which is not generally meaningful, and usually equal to 0xFFFF.
								DWORD   ProccntUsage;  =>The load count of the module (same as GlblcntUsage), which is not generally meaningful, and usually equal to 0xFFFF.
								BYTE    *modBaseAddr;  =>The base address of the module in the context of the owning process.
								DWORD   modBaseSize;   =>The size of the module, in bytes.
								HMODULE hModule;		=>A handle to the module in the context of the owning process.
								TCHAR   szModule[MAX_MODULE_NAME32 + 1];  => the module name.
							    TCHAR   szExePath[MAX_PATH];		=>The module path
							} MODULEENTRY32, *PMODULEENTRY32;
								
							*/

		HANDLE hProcessSnap;
	public:
		DLLInfo(DWORD);
		BOOL DependentDLLDisplay();

};

DLLInfo::DLLInfo(DWORD no){

	PID = no;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,PID);
	if(hProcessSnap == INVALID_HANDLE_VALUE)
	{
		cout<<"Error : Unable to create the snapshot of current thread pool"<<endl;
		return;
	}
	me32.dwSize= sizeof(MODULEENTRY32);
}

BOOL DLLInfo::DependentDLLDisplay(){
	char arr[200];
	if(!Module32First(hProcessSnap,&me32)){  /*  
											 Retrieves information about the first module associated with a process
											 BOOL WINAPI Module32First(
												 _In_    HANDLE          hSnapshot, =>A handle to the snapshot returned from a previous call to the CreateToolhelp32Snapshot function.
												_Inout_ LPMODULEENTRY32 lpme =>A pointer to a MODULEENTRY32 structure.
												);
											 
											 */

			cout<<"Failed to get DLL information"<<endl;
			CloseHandle(hProcessSnap);
			return FALSE;
	}
	cout<<"DEPENDENT DLL OF THIS PROCESS"<<endl;
	do{
		wcstombs_s(NULL,arr,200,me32.szModule,200);  // Converts a sequence of wide characters to a corresponding sequence of multibyte characters.
		cout<<arr<<endl;

	}while(Module32Next(hProcessSnap,&me32));

	CloseHandle(hProcessSnap);
	return TRUE;
}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

class ProcessInfo{

	private:
		DWORD PID;  // typedef unsigned long DWORD;
		DLLInfo *pdobj;
		ThreadInfo *ptobj;
		HANDLE hProcessSnap;  // typedef PVOID HANDLE; typedef void *PVOID;
		PROCESSENTRY32 pe32;  /* Describes an entry from a list of the processes residing in the system address space when a snapshot was taken
								typedef struct tagPROCESSENTRY32 {
								 DWORD     dwSize;  => The size of the structure, in bytes. Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32). If you do not initialize dwSize, Process32First fails.
								 DWORD     cntUsage; =>This member is no longer used and is always set to zero
								 DWORD     th32ProcessID; =>The process identifier.
								 ULONG_PTR(typedef unsigned long ULONG_PTR;) th32DefaultHeapID; =>This member is no longer used and is always set to zero.
								 DWORD     th32ModuleID; =>This member is no longer used and is always set to zero.
								 DWORD     cntThreads; =>The number of execution threads started by the process
								 DWORD     th32ParentProcessID; =>The identifier of the process that created this process (its parent process).
								 LONG      pcPriClassBase; =>The base priority of any threads created by this process.
								 DWORD     dwFlags; =>This member is no longer used, and is always set to zero.
								 TCHAR     szExeFile[MAX_PATH]; =>The name of the executable file for the process. To retrieve the full path to the executable file, call the Module32First function and check the szExePath member of the MODULEENTRY32 structure that is returned. However, if the calling process is a 32-bit process, you must call the QueryFullProcessImageName function to retrieve the full path of the executable file for a 64-bit process.
								 } PROCESSENTRY32, *PPROCESSENTRY32; */
	public:
		ProcessInfo();
		BOOL ProcessDisplay(char *);
		BOOL ProcessLog();
		BOOL ReadLog(DWORD,DWORD,DWORD,DWORD);
		BOOL ProcessSearch(char *);
		BOOL KillProcess(char *);
		void PrintMemoryInfo(DWORD);
		void MemoryStat(DWORD);

};

ProcessInfo::ProcessInfo(){
		
	ptobj = NULL;
	pdobj = NULL;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
	if(hProcessSnap == INVALID_HANDLE_VALUE)
	{
		cout<<"Error : Unable to create the snapshot of running process"<<endl;
		return;
	}
	pe32.dwSize= sizeof(PROCESSENTRY32);

}

BOOL ProcessInfo::ProcessLog()
{
	char* month[] = { "JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC" };
	char FileName[50], arr[200];
	SYSTEMTIME lt;

					/* 
					typedef struct _SYSTEMTIME {
						WORD wYear;
						WORD wMonth;
						 WORD wDayOfWeek;
						WORD wDay;
						WORD wHour;
						WORD wMinute;
						WORD wSecond;
						WORD wMilliseconds;
					} SYSTEMTIME, *PSYSTEMTIME;
					*/
	LOGFILE lobj; //// type def of LOGFILE
			


	FILE *fp;

	GetLocalTime(&lt); // time value reterived

	sprintf_s(FileName, "ProcMonLog %02d_%02d_%02d %s.txt", lt.wHour, lt.wMinute, lt.wDay, month[lt.wMonth - 1]);

	fp = fopen(FileName, "wb");
	if (fp == NULL)
	{
		cout << "\nUnable to create log file" << endl;
		return FALSE;
	}

	cout << "\nLog file successfully gets created as : " << FileName << endl;
	cout << "\nTime of log file creation -> " << lt.wHour << ":" << lt.wMinute << ":" << lt.wDay << "th" << month[lt.wMonth - 1] << endl;

	if (!Process32First(hProcessSnap, &pe32))
	{
											/*
											 BOOL WINAPI Process32First(
												_In_    HANDLE           hSnapshot,
												 _Inout_ LPPROCESSENTRY32 lppe
											);*/
		cout << "\nERROR : In getting first process" << endl;
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do
	{
		wcstombs_s(NULL, arr, 200, pe32.szExeFile, 200); //Converts a sequence of wide characters to a corresponding sequence of multibyte characters.
		strcpy(lobj.ProcessName, arr);
		lobj.pid = pe32.th32ProcessID;
		lobj.ppid = pe32.th32ParentProcessID;
		lobj.thread_cnt = pe32.cntThreads;
		fwrite(&lobj, sizeof(lobj), 1, fp);
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	fclose(fp);
	return TRUE;
}


void ProcessInfo::PrintMemoryInfo(DWORD processID)
{
    HANDLE hProcess;
    PROCESS_MEMORY_COUNTERS pmc;

    // Print the process identifier.

    printf( "\nProcess ID: %u\n", processID );

    // Print information about the memory usage of the process.

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
                                    PROCESS_VM_READ,
                                    FALSE, processID );
    if (NULL == hProcess)
        return;

    if(GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
    {
		cout<<sizeof(pmc);
        printf( "\tPageFaultCount: 0x%08X\n", pmc.PageFaultCount );
        printf( "\tPeakWorkingSetSize: 0x%08X\n", 
                  pmc.PeakWorkingSetSize );
        printf( "\tWorkingSetSize: 0x%08X\n", pmc.WorkingSetSize );
        printf( "\tQuotaPeakPagedPoolUsage: 0x%08X\n", 
                  pmc.QuotaPeakPagedPoolUsage );
        printf( "\tQuotaPagedPoolUsage: 0x%08X\n", 
                  pmc.QuotaPagedPoolUsage );
        printf( "\tQuotaPeakNonPagedPoolUsage: 0x%08X\n", 
                  pmc.QuotaPeakNonPagedPoolUsage );
        printf( "\tQuotaNonPagedPoolUsage: 0x%08X\n", 
                  pmc.QuotaNonPagedPoolUsage );
        printf( "\tPagefileUsage: 0x%08X\n", pmc.PagefileUsage ); 
        printf( "\tPeakPagefileUsage: 0x%08X\n", 
                  pmc.PeakPagefileUsage );
    }

    CloseHandle( hProcess );
}


BOOL ProcessInfo::ProcessDisplay(char *option){
	char arr[200];

	if(!Process32First(hProcessSnap,&pe32)){  
		cout<<"Error In finding the First Process:"<<endl;
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do{

		cout<<endl<<"----------------------------------------------------------";
		wcstombs_s(NULL,arr,200,pe32.szExeFile,200);  // Converts a sequence of wide characters to a corresponding sequence of multibyte characters.
		cout<<endl<<"Process Name"<<arr;
		cout<<endl<<"PID"<<pe32.th32ProcessID;
		cout<<endl<<"Process Parent ID"<<pe32.th32ParentProcessID;
		cout<<endl<<"Number of thread"<<pe32.cntThreads;
		cout<<endl<<"Memory Ussage of process";
		PrintMemoryInfo(pe32.th32ProcessID);
		if((_stricmp(option,"-a")==0) || (_stricmp(option,"-d")==0) || (_stricmp(option,"-t")==0) )
		{
			if((_stricmp(option,"-a")==0) || (_stricmp(option,"-t")==0) ){
				ptobj = new ThreadInfo(pe32.th32ProcessID);
				ptobj->ThreadDisplay();
				delete ptobj;
			}
			if((_stricmp(option,"-d")==0) || (_stricmp(option,"-a")==0) ){
				pdobj = new DLLInfo(pe32.th32ProcessID);
				pdobj->DependentDLLDisplay();
				delete pdobj;
			}

		}
		cout<<endl<<"----------------------------------------------------------";

	}while(Process32Next(hProcessSnap,&pe32));
	CloseHandle(hProcessSnap);
	return TRUE;

}

BOOL ProcessInfo::ReadLog(DWORD hr, DWORD min, DWORD date, DWORD month)
{
	char FileName[50];
	char* montharr[] = { "JAN","FEB","MAR","APR","MAY","JUN","JUL","AUG","SEP","OCT","NOV","DEC" };
	FILE *fp;
	LOGFILE lobj;
	int ret;

		sprintf_s(FileName,"ProcMonLog %02d_%02d_%02d %s.txt",hr,min,date,montharr[month - 1]);

	fp = fopen(FileName, "rb");
	if (fp == NULL)
	{
		cout << "\nUnable to open log file named as " << FileName << endl;
		return FALSE;
	}

	while ((ret = fread(&lobj, 1, sizeof(lobj), fp)) != 0)
	{
		cout << "\n-----------------------------------------------------------" << endl;
		cout << "\nProcess Name : " << lobj.ProcessName << endl;
		cout << "\nProcess ID : " << lobj.pid << endl;
		cout << "\nProcess Parent ID : " << lobj.ppid << endl;
		cout << "\nNo of Threads : " << lobj.thread_cnt << endl;
		cout << "\n-----------------------------------------------------------" << endl;
	}

	fclose(fp);
	return TRUE;
}


BOOL ProcessInfo::ProcessSearch(char *name){
	char arr[200];
	BOOL Flag = FALSE;

	if(!Process32First(hProcessSnap,&pe32)){  
	
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	cout<<endl<<"----------------------------------------------------------";
	do{

		
		wcstombs_s(NULL,arr,200,pe32.szExeFile,200);  // Converts a sequence of wide characters to a corresponding sequence of multibyte characters.

		if(_stricmp(arr,name)==0)
		{
		cout<<endl<<"Process Name"<<arr;
		cout<<endl<<"PID"<<pe32.th32ProcessID;
		cout<<endl<<"Process Parent ID"<<pe32.th32ParentProcessID;
		cout<<endl<<"Number of thread"<<pe32.cntThreads;
		Flag  = TRUE;
		break;
		}
	}while(Process32Next(hProcessSnap,&pe32));
		cout<<endl<<"----------------------------------------------------------";
	
	CloseHandle(hProcessSnap);
	return Flag;

}


BOOL ProcessInfo::KillProcess(char *name){

	char arr[200];
	int pid = -1;
	BOOL bret;
	HANDLE hprocess;
	if(!Process32First(hProcessSnap,&pe32)){  
	
		CloseHandle(hProcessSnap);
		return FALSE;
	}

	do{

	
		wcstombs_s(NULL,arr,200,pe32.szExeFile,200);  // Converts a sequence of wide characters to a corresponding sequence of multibyte characters.

		if(_stricmp(arr,name)==0)
		{
			pid = pe32.th32ProcessID;
			break;
		}
	}while(Process32Next(hProcessSnap,&pe32));
	CloseHandle(hProcessSnap);
	if(pid == -1){
		cout<<"Error There is No such Process"<<endl;
		return FALSE;
	}

	hprocess = OpenProcess(PROCESS_TERMINATE,FALSE,pid);
	if(hprocess==NULL)
	{
		cout<<"Error unable to terminate"<<endl;
		return FALSE;
	}

	bret = TerminateProcess(hprocess,0);
	if(bret == FALSE){
		cout<<"Error Unable to Terminate"<<endl;
		return FALSE;
	}

}

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

BOOL HardwareInfo()
{
	SYSTEM_INFO siSysInfo;  // Contains information about the current computer system. This includes the architecture and type of the processor, the number of processors in the system, the page size, and other such information
						/* 
						typedef struct _SYSTEM_INFO {
						  union {
						DWORD  dwOemId;
					  struct {
					  WORD wProcessorArchitecture;
					 WORD wReserved;
						 };
					 };
						 DWORD     dwPageSize;
						 LPVOID    lpMinimumApplicationAddress;
						LPVOID    lpMaximumApplicationAddress;
						 DWORD_PTR dwActiveProcessorMask;
						 DWORD     dwNumberOfProcessors;
						 DWORD     dwProcessorType;
						 DWORD     dwAllocationGranularity;
						 WORD      wProcessorLevel;
						WORD      wProcessorRevision;
						} SYSTEM_INFO;
						*/

	GetSystemInfo(&siSysInfo);

	cout << "\nOEM ID : " << siSysInfo.dwOemId;  // An obsolete member that is retained for compatibility. Applications should use the wProcessorArchitecture branch of the union.
	cout << "\nNumber of processor : " << siSysInfo.dwNumberOfProcessors;  //The number of logical processors in the current group. To retrieve this value, use the GetLogicalProcessorInformation function.
	cout << "\nPage size : " << siSysInfo.dwPageSize; //The page size and the granularity of page protection and commitment. This is the page size used by the VirtualAlloc function
	cout << "\nProcessor type : " << siSysInfo.dwProcessorType; //An obsolete member that is retained for compatibility. Use the wProcessorArchitecture, wProcessorLevel, and wProcessorRevision members to determine the type of processor
	cout << "\nMinimum application address : " << siSysInfo.lpMinimumApplicationAddress;//A pointer to the lowest memory address accessible to applications and dynamic-link libraries (DLLs)
	cout << "\nMaximum application address : " << siSysInfo.lpMaximumApplicationAddress; //A pointer to the highest memory address accessible to applications and DLLs.
	cout << "\nActive processor mask : " << siSysInfo.dwActiveProcessorMask << endl;//A mask representing the set of processors configured into the system. Bit 0 is processor 0; bit 31 is processor 31.

	return TRUE;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void DisplayHelp()
{
	cout << "\n Information about this tool" << endl;
	cout << "\n ps	:	shows all the information about running process" << endl;
	cout << "\n ps -t	:	shows information of running process with the thread information" << endl;
	cout << "\n ps -d	:	shows information of running process with attached DLL to the process" << endl;
	cout << "\n search: search and display information of specific process " << endl;
	cout<<" \n sysinfo: to display information of hardware configuraion"<<endl;
	cout << "\n log	:	creates the log of all running process in  current folder" << endl;
	cout << "\n readlog:	read log created earlier by the tool" << endl;
	cout << "\n kill	:	kills the running process" << endl;
	cout << "\n clear	:	To clear the screen" << endl;
	cout<<"\nexit to terminate the ProcMon\n";
}



////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

int main(int argc,char *argv[])
{

	BOOL bret; // typedef int BOOL;
	char *ptr = NULL;
	ProcessInfo *ppobj=NULL; // pointer to ProcessInfo
	char command[4][80],str[80];
	int count,min,date,month,hr;
	 
		while(1){
			fflush(stdin);
			strcpy_s(str,"");
			cout<<endl<<"Marvellous :>";
			fgets(str,80,stdin);
			count = sscanf(str,"%s %s %s %s",command[0],command[1],command[2],command[3]);

			if(count == 1){

					if(_stricmp(command[0],"ps") == 0){

						ppobj = new ProcessInfo();
						bret = ppobj->ProcessDisplay("-a");
						if(bret == FALSE)
								cout<<"Error : unable to display process"<<endl;
						delete ppobj;

					}
					else if(_stricmp(command[0],"log") == 0){

						ppobj = new ProcessInfo();
						bret = ppobj->ProcessLog();
						if(bret == FALSE)
								cout<<"Error : unable to create Log"<<endl;
						delete ppobj;

					}

					else if(_stricmp(command[0],"sysinfo") == 0){

								bret = HardwareInfo();
						if(bret == FALSE)
							cout<<"Unable to get Hardware details"<<endl;
					}

					else if(_stricmp(command[0],"readlog") == 0){

						ProcessInfo *ppobj;
						ppobj = new ProcessInfo();
						cout<<"Enter log deails"<<endl;
						cout<<"Hours :";
						cin>>hr;
						cout<<"Minutes :";
						cin>>min;
						cout<<"date :";
						cin>>date;
						cout<<"Months:";
						cin>>month;

						bret = ppobj->ReadLog(hr,min,date,month);
						if(bret == FALSE)
								cout<<"Error : unable to Specific Log file"<<endl;
						delete ppobj;
					
					}
					else if(_stricmp(command[0],"clear") == 0){
						system("cls");

					}
					else if(_stricmp(command[0],"help") == 0){
					DisplayHelp();
						continue;

					}
					else if(_stricmp(command[0],"exit") == 0){
						cout<<endl<<"Terminating the ProcMon"<<endl;
						break;
					}
					else{
						cout<<"Error :Cannot find Command";
					}

			}
			else if(count==2)
			{
				if(_stricmp(command[0],"ps") == 0){

						ppobj = new ProcessInfo();
						bret = ppobj->ProcessDisplay(command[1]);
						if(bret == FALSE)
								cout<<"Error : unable to display process"<<endl;
						delete ppobj;

					}
				else if(_stricmp(command[0],"search") == 0){

						ppobj = new ProcessInfo();
						bret = ppobj->ProcessSearch(command[1]);
						if(bret == FALSE)
								cout<<"Error : There is no Such process"<<endl;
						delete ppobj;
						continue;

					} 

				else if(_stricmp(command[0],"kill") == 0){

						ppobj = new ProcessInfo();
						bret = ppobj->KillProcess(command[1]);
						if(bret == FALSE)
								cout<<"Error : There is no Such process"<<endl;
						else  cout<<command[1]<<"Terminated Succesfully"<<endl;
						delete ppobj;
						continue;

					} 


			}


			else{
				cout<<endl<<"ERROR comand Not Found"<<endl;
			}








		}
	
	return 0;
}