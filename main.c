#include "windows.h"
#include "stdio.h"

PIMAGE_NT_HEADERS WINAPI CheckSumMappedFile(
  PVOID  BaseAddress,
  DWORD  FileLength,
  PDWORD HeaderSum,
  PDWORD CheckSum
);

DWORD WINAPI MapFileAndCheckSumA(
  PCSTR  Filename,
  PDWORD HeaderSum,
  PDWORD CheckSum
);

DWORD WINAPI MapFileAndCheckSumW(
  PCSTR  Filename,
  PDWORD HeaderSum,
  PDWORD CheckSum
);

#ifdef UNICODE
#define MapFileAndCheckSum  MapFileAndCheckSumW
#else
#define MapFileAndCheckSum  MapFileAndCheckSumA
#endif

typedef struct MapHandles
{
  HANDLE FileHandle;
  HANDLE FileMap;
  LPVOID MapView;
} MapHandles;

LPVOID __fastcall BfspMapFileForRead(const WCHAR *lpFileName, DWORD *a2, MapHandles *Handles)
{
  LPVOID result;
  HANDLE file_handle;
  DWORD last_error;
  HANDLE file_map;
  union _LARGE_INTEGER FileSize;
  DWORD *v12;

  result = 0;
  v12 = a2;
  file_handle = CreateFile((LPCSTR)lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
  if ( file_handle == (HANDLE)-1 )
  {
    last_error = GetLastError();
    if ( last_error == 2 || last_error == 3 )
    {
      printf("Unable to open file %s for read because the file or path does not exist", (char *)lpFileName);
    }
    else
    {
      printf("Failed to open file %s for read! Error code = %#x", (char *)lpFileName, last_error);
    }
  }
  else
  {
    if ( GetFileSizeEx(file_handle, &FileSize) )
    {
      if ( FileSize.HighPart )
      {
        last_error = 87;
        printf("File %s is too large!", (char *)lpFileName);
      }
      else
      {
        file_map = CreateFileMappingW(file_handle, 0, 2u, 0, FileSize.LowPart, 0);
        if ( file_map )
        {
          result = MapViewOfFile(file_map, 4u, 0, 0, FileSize.LowPart);
          if ( result )
          {
            *v12 = FileSize.LowPart;
            Handles->FileHandle = file_handle;
            Handles->FileMap = file_map;
            Handles->MapView = result;
            return result;
          }
          last_error = GetLastError();
          printf("MapViewOfFile(%s) failed! Error code = %#x", (char *)lpFileName, last_error);
          CloseHandle(file_map);
        }
        else
        {
          last_error = GetLastError();
          printf("CreateFileMapping(%s) failed! Error code = %#x", (char *)lpFileName, last_error);
        }
      }
    }
    else
    {
      last_error = GetLastError();
      printf("Failed to get file size for %s! Error code = %#x", (char *)lpFileName, last_error);
    }
    CloseHandle(file_handle);
  }
  SetLastError(last_error);
  return result;
}

BOOL __fastcall BfspValidateMappedFileChecksum(PVOID BaseAddress, DWORD FileLength)
{
  BOOL result;
  DWORD HeaderSum;
  DWORD CheckSum;

  CheckSum = -1;
  result = FALSE;
  HeaderSum = 0;

  if ( CheckSumMappedFile(BaseAddress, FileLength, &HeaderSum, &CheckSum) && CheckSum == HeaderSum )
  {
    printf("BfspValidateMappedFileChecksum:\n  HeaderSum: %d\n  CheckSum: %d\n\n", HeaderSum, CheckSum);
    return TRUE;
  }

  printf("BfspValidateMappedFileChecksum:\n  HeaderSum: %d\n  CheckSum: %d\n\n", HeaderSum, CheckSum);
  return result;
}

BOOL __fastcall BfspValidateMappedBootManagerChecksum(PVOID BaseAddress, int a2, int a3)
{
  BOOL result;
  char *v6;
  char *v7;
  char *v8;
  char *i;
  int v10;
  char *v12;

  result = 0;
  if ( BaseAddress && a2 )
  {
    v6 = (char *)BaseAddress + a2;
    v7 = (char *)BaseAddress + 65600;
    v12 = (char *)BaseAddress + a2;
    if ( (char *)BaseAddress + 65600 > (char *)BaseAddress + a2 )
    {
      v7 = (char *)BaseAddress + a2;
    }
    v8 = (char *)BaseAddress;
    for ( i = (char *)BaseAddress + 64; i < v7; i = v8 + 64 )
    {
      v10 = *((DWORD *)i - 1);
      if ( *(WORD *)v8 == 'ZM' && &v8[v10 + 248] < v6 && *(DWORD *)&v8[v10] == 'EP' && *(WORD *)&v8[v10 + 4] == 332 )
      {
        result = BfspValidateMappedFileChecksum(v8, a2 + (BYTE *)BaseAddress - v8);
        if ( result )
        {
          return result;
        }
        v6 = v12;
      }
      else
      {
        result = FALSE;
      }
      v8 += a3;
    }
  }
  return result;
}

BOOL BfspUnmapFile(MapHandles *this)
{
  BOOL result;

  if ( this->MapView )
  {
    result = UnmapViewOfFile((LPCVOID)this->MapView);
  }
  if ( this->FileMap )
  {
    result = CloseHandle((HANDLE)this->FileMap);
  }
  if ( this->FileHandle )
  {
    result =  CloseHandle((HANDLE)this->FileHandle);
  }
  return result;
}

BOOL __fastcall BfspValidateChecksum(const WCHAR *lpFileName, int flag)
{
  BOOL result;
  void *MapHandle;
  void *MapHandle2;
  BOOL checksum_result;
  MapHandles Handles;
  void *var1;
  BOOL var2;
  DWORD FileLength;

  result = FALSE;
  var1 = 0;
  MapHandle = BfspMapFileForRead(lpFileName, &FileLength, &Handles);
  MapHandle2 = MapHandle;
  var1 = MapHandle;
  if ( MapHandle )
  {
    if ( flag )
    {
      result = BfspValidateMappedBootManagerChecksum(MapHandle, FileLength, 8);
      var2 = result;
      if ( result )
        goto unmap;
      checksum_result = BfspValidateMappedBootManagerChecksum(MapHandle2, FileLength, 1);
    }
    else
    {
      checksum_result = BfspValidateMappedFileChecksum(MapHandle, FileLength);
    }
    result = checksum_result;
    var2 = checksum_result;
  }
unmap:
  if ( MapHandle2 )
  {
    BfspUnmapFile(&Handles);
  }
  return result;
}


int main()
{
  DWORD HeaderSum;
  DWORD CheckSum;
  CheckSum = -1;
  HeaderSum = 0;

  MapFileAndCheckSum((PCSTR)"bootmgr", &HeaderSum, &CheckSum);
  printf("MapFileAndCheckSum (cannot be used for compressed boot manager):\n  HeaderSum: %d\n  CheckSum: %d\n\n", HeaderSum, CheckSum);

  if (BfspValidateChecksum((wchar_t *)"bootmgr", 1))
  {
      printf("\nbootmgr checksum valid!");
      return 0;
  }

  printf("\nbootmgr checksum invalid!");

  return 0;
}
