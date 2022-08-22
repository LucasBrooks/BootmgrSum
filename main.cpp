#include <windows.h>
#include <imagehlp.h>
#include <shellapi.h>

HANDLE hConsole;

__forceinline void SwapChars(LPWSTR lpChr1, LPWSTR lpChr2)
{
    WCHAR wcChr1 = *lpChr1;
    *lpChr1 = *lpChr2;
    *lpChr2 = wcChr1;
}

__forceinline LPWSTR ReverseString(LPWSTR lpszBuffer, int i, int j)
{
    while (i < j)
    {
        SwapChars(&lpszBuffer[i++], &lpszBuffer[j--]);
    }
    return lpszBuffer;
}

__forceinline LPWSTR PadWithZero(LPWSTR lpszBuffer, UINT uiDigits)
{
    WCHAR szNumber[9];
    UINT uiLength = (UINT)lstrlen((LPCWSTR)lpszBuffer);
    if (uiLength < uiDigits && uiDigits <= 8)
    {
        lstrcpy((LPWSTR)szNumber, (LPCWSTR)lpszBuffer);
        for (UINT i = 0; i < (uiDigits - uiLength); i++)
        {
            lpszBuffer[i] = '0';
        }
        lstrcpy((LPWSTR)(lpszBuffer + (uiDigits - uiLength)), (LPCWSTR)szNumber);
    }
    return lpszBuffer;
}

LPWSTR UIntToString(UINT uiValue, LPWSTR lpszBuffer, UINT uiBase, UINT uiPad = 0)
{
    if (uiBase < 2 || uiBase > 32)
    {
        return lpszBuffer;
    }
    UINT n = uiValue;
    int i = 0;
    while (n)
    {
        int r = n % uiBase;
        if (r >= 10)
        {
            lpszBuffer[i++] = 65 + (r - 10);
        }
        else
        {
            lpszBuffer[i++] = 48 + r;
        }
        n /= uiBase;
    }
    if (i == 0)
    {
        lpszBuffer[i++] = '0';
    }
    if (uiBase < 0 && uiBase == 10)
    {
        lpszBuffer[i++] = '-';
    }
    lpszBuffer[i] = '\0';
    return PadWithZero(ReverseString(lpszBuffer, 0, i - 1), uiPad);
}

void PrintLine(LPCWSTR lpszLine)
{
    WriteConsole(hConsole, (VOID*)lpszLine, lstrlen(lpszLine), (LPDWORD)NULL, (LPVOID)NULL);
}

class BootmgrChecksum
{
public:
    DWORD dwHeaderSum;
    DWORD dwCorrectSum;
    DWORD dwChecksumPos;
    BOOL bIsChecksumValid;
    BOOL bIsPosValid;

private:
    HANDLE hFile;
    HANDLE hFileMap;
    LPVOID pvMapView;
    DWORD dwFileSize;

public:
    BootmgrChecksum(LPCWSTR lpszFileName)
    {
        dwHeaderSum = 0;
        dwCorrectSum = 0;
        dwChecksumPos = 0;
        bIsChecksumValid = FALSE;
        bIsPosValid = FALSE;
        hFile = (HANDLE)NULL;
        hFileMap = (HANDLE)NULL;
        pvMapView = (LPVOID)NULL;
        dwFileSize = 0;
        MapFileForRead(lpszFileName);
    }

    ~BootmgrChecksum()
    {
        if (pvMapView)
        {
            UnmapViewOfFile((LPCVOID)pvMapView);
        }
        if (hFileMap)
        {
            CloseHandle(hFileMap);
        }
        if (hFile)
        {
            CloseHandle(hFile);
        }
    }

    void MapFileForRead(LPCWSTR lpszFileName)
    {
        DWORD dwLastError;
        LARGE_INTEGER liFileSize;

        hFile = CreateFile(lpszFileName, GENERIC_READ, FILE_SHARE_READ, (LPSECURITY_ATTRIBUTES)NULL, OPEN_EXISTING, 0, (HANDLE)NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            if (GetFileSizeEx(hFile, &liFileSize))
            {
                if (liFileSize.HighPart)
                {
                    dwLastError = ERROR_INVALID_PARAMETER;
                }
                else
                {
                    dwFileSize = liFileSize.LowPart;
                    hFileMap = CreateFileMapping(hFile, (LPSECURITY_ATTRIBUTES)NULL, PAGE_READONLY, 0, dwFileSize, (LPCWSTR)NULL);
                    if (hFileMap)
                    {
                        pvMapView = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, (SIZE_T)dwFileSize);
                        if (pvMapView)
                        {
                            return;
                        }
                        dwLastError = GetLastError();
                        CloseHandle(hFileMap);
                        hFileMap = (HANDLE)NULL;
                    }
                    else
                    {
                        dwLastError = GetLastError();
                    }
                }
            }
            else
            {
                dwLastError = GetLastError();
            }
            CloseHandle(hFile);
            hFile = (HANDLE)NULL;
        }
        else
        {
            dwLastError = GetLastError();
            hFile = (HANDLE)NULL;
        }
        SetLastError(dwLastError);
    }

    BOOL ValidateMappedFileChecksum(LPVOID pvFileOffset, DWORD dwFileLength)
    {
        if (CheckSumMappedFile((PVOID)pvFileOffset, dwFileLength, &dwHeaderSum, &dwCorrectSum))
        {
            bIsChecksumValid = TRUE;
            if (dwHeaderSum == dwCorrectSum)
            {
                return TRUE;
            }
        }
        else
        {
            dwHeaderSum = 0;
            dwCorrectSum = 0;
        }
        return FALSE;
    }

    DWORD GetChecksumFieldPos(LPVOID pvExeOffset)
    {
        return (DWORD)(((PIMAGE_DOS_HEADER)pvExeOffset)->e_lfanew + 0x58);
    }

    BOOL ValidateMappedBootManagerChecksum(DWORD dwAlignment)
    {
        LPBYTE lpFileEnd, lpHeaderMax, lpExeHeader;
        LPBYTE i;
        DWORD dwNewHdr;

        if (pvMapView && dwFileSize)
        {
            lpFileEnd = (LPBYTE)pvMapView + dwFileSize;
            lpHeaderMax = (LPBYTE)pvMapView + 65600;
            if (lpHeaderMax > lpFileEnd)
            {
                lpHeaderMax = lpFileEnd;
            }
            lpExeHeader = (LPBYTE)pvMapView;
            for (i = (LPBYTE)pvMapView + 64; i < lpHeaderMax; i = lpExeHeader + 64)
            {
                dwNewHdr = *((LPDWORD)i - 1);
                if (*(LPWORD)lpExeHeader == IMAGE_DOS_SIGNATURE && &lpExeHeader[dwNewHdr + 248] < lpFileEnd && *(LPDWORD)&lpExeHeader[dwNewHdr] == IMAGE_NT_SIGNATURE && *(LPWORD)&lpExeHeader[dwNewHdr + 4] == IMAGE_FILE_MACHINE_I386)
                {
                    dwChecksumPos = (DWORD)(lpExeHeader - (LPBYTE)pvMapView) + GetChecksumFieldPos(lpExeHeader);
                    bIsPosValid = TRUE;
                    if (ValidateMappedFileChecksum((LPVOID)lpExeHeader, dwFileSize + (DWORD)((LPBYTE)pvMapView - lpExeHeader)))
                    {
                        return TRUE;
                    }
                }
                lpExeHeader += dwAlignment;
            }
        }
        return FALSE;
    }

    BOOL ValidateChecksum(LPCWSTR lpszFileName, BOOL bIsBootMgr)
    {
        BOOL bResult = FALSE;

        if (pvMapView)
        {
            if (bIsBootMgr)
            {
                // 8-byte alignment
                bResult = ValidateMappedBootManagerChecksum(8);
                if (!bResult)
                {
                    // try 1-byte alignment
                    bResult = ValidateMappedBootManagerChecksum(1);
                }
            }
            else
            {
                bResult = ValidateMappedFileChecksum(pvMapView, dwFileSize);
            }
        }
        return bResult;
    }
};


int main(int argc, LPCWSTR *argv)
{
    WCHAR szNumber[9];

    if (argc < 2)
    {
        PrintLine((LPCWSTR)L"BootmgrSum <path-to-bootmgr>\r\n");
        return -1;
    }
    BootmgrChecksum bmChk = BootmgrChecksum(argv[1]);
    HRESULT hr = HRESULT_FROM_WIN32(GetLastError());
    if (hr < 0)
    {
        PrintLine((LPCWSTR)L"Unable to read input file!\r\n");
        return -1;
    }
    if (bmChk.ValidateChecksum(argv[1], TRUE))
    {
        PrintLine((LPCWSTR)L"Checksum is valid.\r\n");
    }
    else
    {
        if (bmChk.bIsChecksumValid && bmChk.bIsPosValid)
        {
            PrintLine((LPCWSTR)L"Checksum is invalid!\r\n\r\nCurrent checksum:  0x");
            PrintLine((LPCWSTR)UIntToString(bmChk.dwHeaderSum, szNumber, 16, 8));
            PrintLine((LPCWSTR)L"\r\nExpected checksum: 0x");
            PrintLine((LPCWSTR)UIntToString(bmChk.dwCorrectSum, szNumber, 16, 8));
            PrintLine((LPCWSTR)L"\r\nChecksum field at: 0x");
            PrintLine((LPCWSTR)UIntToString(bmChk.dwChecksumPos, szNumber, 16, 8));
            PrintLine((LPCWSTR)L"\r\n");
        }
        else
        {
            PrintLine((LPCWSTR)L"\"");
            PrintLine(argv[1]);
            PrintLine((LPCWSTR)L"\" is not a valid legacy BIOS boot manager or does not contain a valid PE stub!\r\n");
        }
    }
    return 0;
}

int WinStart()
{
    hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    int argc = 0;
    LPCWSTR* argv = (LPCWSTR *)CommandLineToArgvW(GetCommandLine(), &argc);
    return main(argc, argv);
}
