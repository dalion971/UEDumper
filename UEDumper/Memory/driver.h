﻿// ReSharper disable CppNonInlineFunctionDefinitionInHeaderFile
#pragma once

//add any other includes here your driver might use
#include <Windows.h>
#include <tlhelp32.h>
#include "Driver/DRV.h"
#include "kdmapper/include/kdmapper.hpp"
#include "Driver/Driver.hpp"

/*
██████╗░██╗░░░░░███████╗░█████╗░░██████╗███████╗  ██████╗░███████╗░█████╗░██████╗░██╗
██╔══██╗██║░░░░░██╔════╝██╔══██╗██╔════╝██╔════╝  ██╔══██╗██╔════╝██╔══██╗██╔══██╗██║
██████╔╝██║░░░░░█████╗░░███████║╚█████╗░█████╗░░  ██████╔╝█████╗░░███████║██║░░██║██║
██╔═══╝░██║░░░░░██╔══╝░░██╔══██║░╚═══██╗██╔══╝░░  ██╔══██╗██╔══╝░░██╔══██║██║░░██║╚═╝
██║░░░░░███████╗███████╗██║░░██║██████╔╝███████╗  ██║░░██║███████╗██║░░██║██████╔╝██╗
╚═╝░░░░░╚══════╝╚══════╝╚═╝░░╚═╝╚═════╝░╚══════╝  ╚═╝░░╚═╝╚══════╝╚═╝░░╚═╝╚═════╝░╚═╝
*/


/// here should be your driver functions
///	DO NOT call any of those functions from any class,
///	they should only get called from the memory class (memory.cpp and memory.h)
/// DO NOT include this file in any other file, you might get linker errors!
/// ANY CHANGES you do to the params in functions, make sure you also edit the memory.cpp and memory.h file!

//global variables here
HANDLE procHandle = nullptr;

//in case you need to initialize anything BEFORE your com works, you can do this in here.
//this function IS NOT DESIGNED to already take the process name as input or anything related to the target process
//use the function "load" below which will contain data about the process name
bool load_driver()
{


	system("sc config vgc start= disabled & sc config vgk start= disabled & net stop vgc & net stop vgk & sc delete vgc & sc delete vgk & taskkill /IM vgtray.exe");
	bool free = false; //
	bool mdlMode = true;
	bool passAllocationPtr = false;

	HANDLE iqvw64e_device_handle = 0;

	if (intel_driver::IsRunning())
	{
		return false;
	}

	iqvw64e_device_handle = intel_driver::Load();

	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(iqvw64e_device_handle, (BYTE*)kernel_driver, 0, 0, free, true, kdmapper::AllocationMode::AllocateMdl, passAllocationPtr, nullptr, &exitCode))
	{

		intel_driver::Unload(iqvw64e_device_handle);
		return false;

	}
	intel_driver::Unload(iqvw64e_device_handle);
	Sleep(500);

	return true;


}
inline void init()
{
    //...
    // kdmapper
    if (!load_driver())
    {
        MessageBoxA(NULL, "Failed to load driver!", "Error", MB_ICONERROR);
        exit(1);
    }
    driver->Init();
}

uint64_t _getBaseAddress(const wchar_t* processName, int& pid);

void attachToProcess(const int& pid);

/**
 * \brief use this function to initialize the target process
 * \param processName process name as input
 * \param baseAddress base address of the process gets returned
 * \param processID process id of the process gets returned
 */
inline void loadData(std::string& processName, uint64_t& baseAddress, int& processID)
{
    const auto name = std::wstring(processName.begin(), processName.end());

    baseAddress = _getBaseAddress(name.c_str(), processID);

    attachToProcess(processID);
}

/**
 * \brief read function (replace with your read logic)
 * \param address memory address to read from
 * \param buffer memory address to write to
 * \param size size of memory to read (expects the buffer/address to have this size too)
 */
inline void _read(const void* address, void* buffer, const DWORD64 size)
{
   driver->ReadMemory((PVOID)address, buffer, size);
}


/**
 * \brief write function (replace with your write logic)
 * \param address memory address to write to
 * \param buffer memory address to write from
 * \param size size of memory to write (expects the buffer/address to have this size too)
 */
inline void _write(void* address, const void* buffer, const DWORD64 size)
{
    driver->WriteMemory(address, (PVOID)buffer, size);
}


/**
 * \brief gets the process base address. If you adjust the params, make sure to change them in memory.cpp too
 * \param processName the name of the process
 * \param pid returns the process id
 * \return process base address
 */
uint64_t _getBaseAddress(const wchar_t* processName, int& pid)
{
    uint64_t baseAddress = 0;

    if (!pid)
    {
        // Get a handle to the process
        const HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcess == INVALID_HANDLE_VALUE) {
            return false;
        }

        // Iterate through the list of processes to find the one with the given filename
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
        if (!Process32First(hProcess, &pe32)) {
            CloseHandle(hProcess);
            return false;
        }
        while (Process32Next(hProcess, &pe32)) {
            if (wcscmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        }

        CloseHandle(hProcess);
    }

    // Get the base address of the process in memory
    if (pid != 0) {
        const HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hModule != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
            if (Module32First(hModule, &me32)) {
                baseAddress = reinterpret_cast<DWORD64>(me32.modBaseAddr);
            }
            CloseHandle(hModule);
        }
    }

    // Clean up and return

    return baseAddress;
}

/**
 * \brief this function might not be needed for your driver, this just attaches to the process
 * \param pid process id of the target process
 */
void attachToProcess(const int& pid)
{
    driver->AttachByID(pid);
}