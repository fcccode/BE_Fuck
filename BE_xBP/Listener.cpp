#include "Listener.hpp"
#include <sstream>
#include <fstream>

#define LOGPATH "D:\\MyProjects\\VSProjects\\BE_Fuck\\log_listener.txt"

std::ofstream LogFile;
std::ostringstream OutputBuffer;

void hex_dump(PVOID Buffer, size_t length, std::ostringstream& OutputBuffer) {
    OutputBuffer.str("");
    OutputBuffer.clear();
    OutputBuffer << "│ ";
    for (size_t i = 0; i < length; i++)
    {
        OutputBuffer.fill('0');
        OutputBuffer.width(2);
        OutputBuffer << std::hex << (int)(*((unsigned char *)Buffer + i));
        OutputBuffer << " ";
    }
    OutputBuffer << std::endl << "│ ";
    for (size_t i = 0; i < length; i++)
    {
        OutputBuffer << *((unsigned char *)Buffer + i);
    }
}

namespace BE
{
    namespace Listener
    {
        XDriver* XDriver::Instance;
        XDriver::p_NtCreateFile XDriver::o_NtCreateFile;
        XDriver::p_ZwReadFile XDriver::o_ZwReadFile;
        XDriver::p_ZwWriteFile XDriver::o_ZwWriteFile;
        XDriver* XDriver::GetInstance()
        {
            if (!Instance)
                Instance = new XDriver;
            return Instance;
        }
        XDriver::XDriver()
        {
            o_NtCreateFile = 0;
            o_ZwReadFile = 0;
            o_ZwWriteFile = 0;
        }
        XDriver::~XDriver()
        {
            if (Instance)
                delete Instance;
        }
        bool XDriver::Init()
        {
            LogFile = std::ofstream(LOGPATH);
            return detour_DriverConnection(true);
        }
        bool XDriver::Uninit()
        {
            return detour_DriverConnection(false);
        }

        bool XDriver::detour_DriverConnection(bool Status)
        {
            VirtualizerStart();
            BOOL Result = 1;
            o_NtCreateFile = o_NtCreateFile ? o_NtCreateFile : reinterpret_cast<p_NtCreateFile>(reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateFile")));
            if (!o_NtCreateFile)
                Result = 0;
            o_ZwReadFile = o_ZwReadFile ? o_ZwReadFile : reinterpret_cast<p_ZwReadFile>(reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwReadFile")));
            if (!o_ZwReadFile)
                Result = 0;
            o_ZwWriteFile = o_ZwWriteFile ? o_ZwWriteFile : reinterpret_cast<p_ZwWriteFile>(reinterpret_cast<DWORD_PTR>(GetProcAddress(GetModuleHandle("ntdll.dll"), "ZwWriteFile")));
            if (!o_ZwWriteFile)
                Result = 0;

            if (DetourTransactionBegin() != NO_ERROR ||
                DetourUpdateThread(GetCurrentThread()) != NO_ERROR ||
                (Status ? DetourAttach : DetourDetach)(&(PVOID&)o_NtCreateFile, NtCreateFile_Hook) != NO_ERROR ||
                (Status ? DetourAttach : DetourDetach)(&(PVOID&)o_ZwReadFile, ZwReadFile_Hook) != NO_ERROR ||
                (Status ? DetourAttach : DetourDetach)(&(PVOID&)o_ZwWriteFile, ZwWriteFile_Hook) != NO_ERROR ||
                DetourTransactionCommit() != NO_ERROR)
                Result = 0;
            VirtualizerEnd();
            return Result;
        }


        NTSTATUS NTAPI XDriver::NtCreateFile_Hook(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
        {
            VirtualizerStart();
            DWORD dwWritten = 0;
            NTSTATUS Status = -1;
            if (ObjectAttributes &&
                ObjectAttributes->ObjectName &&
                ObjectAttributes->ObjectName->Buffer &&
                wcsstr(ObjectAttributes->ObjectName->Buffer, L"BattlEye") &&
                wcsstr(ObjectAttributes->ObjectName->Buffer, L"pipe")) // the pipename is \\??\\pipe\\BattlEye 内核名字和应用层不一样
            {

                DbgLog::Log("[BEService] CreateFile: %ls", ObjectAttributes->ObjectName->Buffer);
                LogFile << "[BEService] NamedPipe Created!";
                LogFile.flush();

                return o_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
            }
            VirtualizerEnd();
            return o_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

        };


        BOOL GetFileNameFromHandle(HANDLE hFile, std::string& fileName)
        {
            DWORD size = MAX_PATH * sizeof(WCHAR) + sizeof(DWORD);
            FILE_NAME_INFO* Path = (FILE_NAME_INFO*)malloc(size);
            memset(Path, 0, size);
            BOOL ret = GetFileInformationByHandleEx(hFile, FILE_INFO_BY_HANDLE_CLASS::FileNameInfo, Path, size);
            if (!ret) return false;
            std::wstring wstr = Path->FileName;
            fileName = std::string(wstr.begin(), wstr.end());
            free(Path);
            return true;
        }

        NTSTATUS NTAPI XDriver::ZwReadFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER   ByteOffset, PULONG Key)
        {
            std::string fileName;
            if (!GetFileNameFromHandle(FileHandle, fileName))
            {
                fileName = "unknown";
            }

            NTSTATUS Status = o_ZwReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

            bool isBattlEye = fileName.compare("\\BattlEye") == 0;
            if (isBattlEye) {
                if (NT_SUCCESS(Status)) {
                    DbgLog::Log("[BEService] ReadFile from:%s", fileName);
                    LogFile << "[BEService] ReadFile from: " << fileName << std::endl;
                    hex_dump(Buffer, Length, OutputBuffer);
                    LogFile << "│ [ID: " << (DWORD)reinterpret_cast<CHAR*>(Buffer)[0] << "][Recv] [" << Length << " bytes]\n" << OutputBuffer.str() << std::endl << std::endl;
                    LogFile.flush();
                }
                else {
                    DbgLog::Log("[BEService] ReadFile from:%ls error:%d", fileName, Status);
                    LogFile << "[BEService] ReadFile from: " << fileName << " error:" << Status << std::endl;
                }
            }
            return Status;
        }

        NTSTATUS NTAPI XDriver::ZwWriteFile_Hook(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE  ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER   ByteOffset, PULONG Key)
        {
            std::string fileName;
            if (!GetFileNameFromHandle(FileHandle, fileName))
            {
                fileName = "unknown";
            }

            NTSTATUS Status = o_ZwWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);

            bool isBattlEye = fileName.compare("\\BattlEye") == 0;
            if (isBattlEye) {
                if (NT_SUCCESS(Status)) {
                    DbgLog::Log("[BEService] WriteFile from:%s", fileName);
                    LogFile << "[BEService] WriteFile from: " << fileName << std::endl;
                    hex_dump(Buffer, Length, OutputBuffer);
                    LogFile << "│ [ID: " << (DWORD)reinterpret_cast<CHAR*>(Buffer)[0] << "][Send] [" << Length << " bytes]\n" << OutputBuffer.str() << std::endl << std::endl;
                    LogFile.flush();

                }
                else {
                    DbgLog::Log("[BEService] WriteFile from:%ls error:%d", fileName, Status);
                    LogFile << "[BEService] WriteFile from: " << fileName << " error:" << Status << std::endl;
                }
            }
            return Status;
        }
    }
}