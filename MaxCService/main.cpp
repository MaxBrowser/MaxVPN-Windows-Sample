#include <windows.h>
#include <string>
#include <iostream>
#include <sstream>

// Define the named pipe name
#define PIPE_NAME L"\\\\.\\pipe\\WireGuardInterfacePipe"
#define BUFFER_SIZE 4096

// Global service handle and stop event
SERVICE_STATUS_HANDLE g_ServiceStatusHandle;
HANDLE g_ServiceStopEvent = NULL;

// Service name
wchar_t g_ServiceNameArray[] = L"WireGuardInterfaceService";
LPWSTR g_ServiceName = g_ServiceNameArray;

// Function prototypes
VOID WINAPI ServiceMain(DWORD dwArgc, LPWSTR* lpArgv);
VOID WINAPI ServiceCtrlHandler(DWORD dwCtrl);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

// Helper function to write to the event log
void WriteToEventLog(const std::wstring& message, WORD type = EVENTLOG_ERROR_TYPE);

int main() {
    SERVICE_TABLE_ENTRYW ServiceTable[] = {
        {g_ServiceName, ServiceMain},
        {NULL, NULL}
    };

    if (!StartServiceCtrlDispatcherW(ServiceTable)) {
        WriteToEventLog(L"StartServiceCtrlDispatcher failed.", EVENTLOG_ERROR_TYPE);
        return GetLastError();
    }

    return 0;
}

VOID WINAPI ServiceMain(DWORD dwArgc, LPWSTR* lpArgv) {
    g_ServiceStatusHandle = RegisterServiceCtrlHandlerW(g_ServiceName, ServiceCtrlHandler);
    if (!g_ServiceStatusHandle) {
        WriteToEventLog(L"RegisterServiceCtrlHandler failed.", EVENTLOG_ERROR_TYPE);
        return;
    }

    // Report initial status to the SCM
    SERVICE_STATUS ssStatus;
    ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ssStatus.dwServiceSpecificExitCode = 0;
    ssStatus.dwWin32ExitCode = NO_ERROR;
    ssStatus.dwCurrentState = SERVICE_START_PENDING;
    ssStatus.dwControlsAccepted = 0;

    if (!SetServiceStatus(g_ServiceStatusHandle, &ssStatus)) {
        WriteToEventLog(L"SetServiceStatus (START_PENDING) failed.", EVENTLOG_ERROR_TYPE);
        return;
    }

    // Create a service stop event. This event will be signaled when the service is to stop.
    g_ServiceStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (g_ServiceStopEvent == NULL) {
        ssStatus.dwCurrentState = SERVICE_STOPPED;
        ssStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_ServiceStatusHandle, &ssStatus);
        WriteToEventLog(L"CreateEvent failed.", EVENTLOG_ERROR_TYPE);
        return;
    }

    // Create a worker thread to perform the actual service work.
    HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
    if (hThread == NULL) {
        ssStatus.dwCurrentState = SERVICE_STOPPED;
        ssStatus.dwWin32ExitCode = GetLastError();
        SetServiceStatus(g_ServiceStatusHandle, &ssStatus);
        WriteToEventLog(L"CreateThread failed.", EVENTLOG_ERROR_TYPE);
        CloseHandle(g_ServiceStopEvent);
        return;
    }

    // Report running status to the SCM
    ssStatus.dwCurrentState = SERVICE_RUNNING;
    ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
    if (!SetServiceStatus(g_ServiceStatusHandle, &ssStatus)) {
        WriteToEventLog(L"SetServiceStatus (RUNNING) failed.", EVENTLOG_ERROR_TYPE);
    }

    // Wait for the stop event
    WaitForSingleObject(g_ServiceStopEvent, INFINITE);

    // Service stop initiated
    ssStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(g_ServiceStatusHandle, &ssStatus);

    // Clean up
    CloseHandle(hThread);
    CloseHandle(g_ServiceStopEvent);

    ssStatus.dwCurrentState = SERVICE_STOPPED;
    ssStatus.dwWin32ExitCode = NO_ERROR;
    SetServiceStatus(g_ServiceStatusHandle, &ssStatus);
}

VOID WINAPI ServiceCtrlHandler(DWORD dwCtrl) {
    switch (dwCtrl) {
    case SERVICE_CONTROL_STOP:
        // Signal the service to stop
        SetEvent(g_ServiceStopEvent);
        break;
    default:
        break;
    }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
    HANDLE hPipe;
    char buffer[BUFFER_SIZE];
    DWORD dwRead;
    bool fConnected = FALSE;
    std::wstring jsonMessage;

    while (WaitForSingleObject(g_ServiceStopEvent, 0) == WAIT_TIMEOUT) {
        WriteToEventLog(L"ServiceWorkerThread: Creating named pipe...", EVENTLOG_INFORMATION_TYPE);

        hPipe = CreateNamedPipeW(
            PIPE_NAME,                 // Pipe name
            PIPE_ACCESS_DUPLEX,        // Read/write access
            PIPE_TYPE_BYTE |           // Byte type pipe
            PIPE_READMODE_BYTE |       // Byte-read mode
            PIPE_WAIT,                // Blocking mode
            1,                         // Max. instances
            BUFFER_SIZE,               // Output buffer size
            BUFFER_SIZE,               // Input buffer size
            -1, // Default timeout
            NULL);                     // Security attributes

        if (hPipe == INVALID_HANDLE_VALUE) {
            std::wostringstream oss;
            oss << L"CreateNamedPipe failed, GLE=" << GetLastError();
            WriteToEventLog(oss.str(), EVENTLOG_ERROR_TYPE);
            Sleep(5000); // Wait before retrying
            continue;
        }

        WriteToEventLog(L"ServiceWorkerThread: Waiting for client connection...", EVENTLOG_INFORMATION_TYPE);

        fConnected = ConnectNamedPipe(hPipe, NULL);

        if (fConnected) {
            WriteToEventLog(L"ServiceWorkerThread: Client connected.", EVENTLOG_INFORMATION_TYPE);

            // Read data from the client
            while (ReadFile(hPipe, buffer, BUFFER_SIZE - 1, &dwRead, NULL) != FALSE) {
                if (dwRead > 0) {
                    buffer[dwRead] = '\0'; // Null-terminate the buffer
                    std::string receivedData(buffer, dwRead);
                    jsonMessage += std::wstring(receivedData.begin(), receivedData.end());

                    // Check if we have a complete JSON message (you might need more sophisticated logic here)
                    if (receivedData.find('}') != std::string::npos) {
                        std::wostringstream oss;
                        oss << L"Received JSON: " << jsonMessage;
                        WriteToEventLog(oss.str(), EVENTLOG_INFORMATION_TYPE);

                        // **TODO: Process the JSON message here.**
                        // You would typically parse the jsonMessage using a JSON library
                        // and then handle the "Command" and "Payload".
                        // For demonstration, let's just clear the message buffer after processing
                        jsonMessage.clear();
                    }
                }
                else {
                    // Client disconnected or no more data
                    break;
                }
            }

            DisconnectNamedPipe(hPipe);
            WriteToEventLog(L"ServiceWorkerThread: Client disconnected.", EVENTLOG_INFORMATION_TYPE);
        }
        else {
            std::wostringstream oss;
            oss << L"ConnectNamedPipe failed, GLE=" << GetLastError();
            WriteToEventLog(oss.str(), EVENTLOG_ERROR_TYPE);
            CloseHandle(hPipe);
            Sleep(5000); // Wait before retrying
        }

        CloseHandle(hPipe);
    }

    WriteToEventLog(L"ServiceWorkerThread: Exiting.", EVENTLOG_INFORMATION_TYPE);
    return 0;
}

void WriteToEventLog(const std::wstring& message, WORD type) {
    HANDLE hEventSource = RegisterEventSourceW(NULL, g_ServiceName);
    if (hEventSource != NULL) {
        LPCWSTR lpszStrings[1];
        lpszStrings[0] = message.c_str();
        ReportEventW(hEventSource, type, 0, 0, NULL, 1, 0, lpszStrings, NULL);
        DeregisterEventSource(hEventSource);
    }
}