#include "Windows.h"
#include <iostream>
#include <Logs.h>
#include <QCoreApplication>
#include <QFile>
#define CheckArg(list,arg)  list.indexOf(arg)!=-1
void Usage(){
    LOG::le("Examples:\n"
            "   PEParser.exe PE[exe,dll file] Option[-ALL,-SECTIONS,-IMPORTS]\n"
            "   PEParser.exe pe -ALL [read all info]\n"
            "   PEParser.exe pe -SECTIONS [read all sections]\n"
            "   PEParser.exe pe -HEADERS [read all Headers]\n");
    LOG::SetColor(7);
    exit(EXIT_FAILURE);
}
int main(int argc, char* argv[]) {
    QCoreApplication app(argc,argv);
    QStringList args=app.arguments();
    LOG::resizeWindow(80,45);
    LOG::customText("PE Parser v1.0.0",20);
    bool Imports=false,Sections=false,Headers=false;
    if(args.count()==1)
    {
        LOG::dieError("error input pe file name or full path");
        Usage();
    }else if(args.count()>3){
        LOG::dieError("error count input arguments");
        Usage();
    }
    if(CheckArg(args,"-ALL")){
        Imports=true;
        Sections=true;
        Headers=true;
        LOG::la("Option");LOG::lp("All");
    }else if(CheckArg(args,"-HEADERS")){
        Headers=true;
        LOG::la("Option");LOG::lp("Headers");
    }else if(CheckArg(args,"-SECTIONS")){
        Sections=true;
        LOG::la("Option");LOG::lp("Sections");
    }else if(CheckArg(args,"-IMPORTS")){
        Imports=true;
        LOG::la("Option");LOG::lp("Imports");
    }else{
        LOG::dieError("error input arguments");
    }
    LOG::la("PE File");LOG::die("%s",argv[1]);
    LOG::la("PE Size");LOG::lp(QString::number(QFile(argv[1]).size()));
    const int MAX_FILEPATH = 255;
    char fileName[MAX_FILEPATH] = {0};
    memcpy_s(&fileName, MAX_FILEPATH, argv[1], MAX_FILEPATH);
    HANDLE file = NULL;
    DWORD fileSize = NULL;
    DWORD bytesRead = NULL;
    LPVOID fileData = NULL;
    PIMAGE_DOS_HEADER dosHeader = {};
    PIMAGE_NT_HEADERS imageNTHeaders = {};
    PIMAGE_SECTION_HEADER sectionHeader = {};
    PIMAGE_SECTION_HEADER importSection = {};
    IMAGE_IMPORT_DESCRIPTOR* importDescriptor = {};
    PIMAGE_THUNK_DATA thunkData = {};
    DWORD thunk = NULL;
    DWORD rawOffset = NULL;

    // open file
    file = CreateFileA(fileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
    {
        LOG::dieError("Could not read file :%s ",fileName);
    }
    // allocate heap
    fileSize = GetFileSize(file, NULL);
    fileData = HeapAlloc(GetProcessHeap(), 0, fileSize);

    // read file bytes to memory
    ReadFile(file, fileData, fileSize, &bytesRead, NULL);

    // IMAGE_DOS_HEADER
    dosHeader = (PIMAGE_DOS_HEADER)fileData;
    if(Headers){
        LOG::customText("DOS HEADER");
        LOG::la("Magic number");LOG::die("0x%x", dosHeader->e_magic);

        //    LOG::la();LOG::die(, );
        LOG::la("Bytes on last page of file");LOG::die("0x%x", dosHeader->e_cblp);
        LOG::la("Pages in file");LOG::die("0x%x", dosHeader->e_cp);
        LOG::la("Relocations");LOG::die("0x%x", dosHeader->e_crlc);
        LOG::la("Size of header in paragraphs");LOG::die("0x%x", dosHeader->e_cparhdr);
        LOG::la("Minimum extra paragraphs needed");LOG::die("0x%x", dosHeader->e_minalloc);
        LOG::la("Maximum extra paragraphs needed");LOG::die("0x%x", dosHeader->e_maxalloc);
        LOG::la("Initial (relative) SS value");LOG::die("0x%x", dosHeader->e_ss);
        LOG::la("Initial SP value");LOG::die("0x%x", dosHeader->e_sp);
        LOG::la("Checksum");LOG::die("0x%x", dosHeader->e_csum);
        LOG::la("Initial IP value");LOG::die("0x%x", dosHeader->e_ip);
        LOG::la("tInitial (relative) CS value");LOG::die("0x%x", dosHeader->e_cs);
        LOG::la("File address of relocation table");LOG::die("0x%x", dosHeader->e_lfarlc);
        LOG::la("Overlay number");LOG::die("0x%x", dosHeader->e_ovno);
        LOG::la("OEM identifier (for e_oeminfo)");LOG::die("0x%x", dosHeader->e_oemid);
        LOG::la("OEM information; e_oemid specific");LOG::die("0x%x", dosHeader->e_oeminfo);

        LOG::la("File address of new exe header");LOG::die("0x%x", dosHeader->e_lfanew);
    }
    // IMAGE_NT_HEADERS
    imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD)fileData + dosHeader->e_lfanew);
    if(Headers){
        LOG::customText("NT HEADERS");

        LOG::la("Signature");LOG::die("%x", imageNTHeaders->Signature);
        // FILE_HEADER
        LOG::customText("FILE HEADER");
        LOG::la("Machine");LOG::die("0x%x", imageNTHeaders->FileHeader.Machine);
        LOG::la("Number of Sections");LOG::die("0x%x", imageNTHeaders->FileHeader.NumberOfSections);
        LOG::la("Time Stamp");LOG::die("0x%x  ", imageNTHeaders->FileHeader.TimeDateStamp);
        LOG::la("Pointer to Symbol Table");LOG::die("0x%x", imageNTHeaders->FileHeader.PointerToSymbolTable);
        LOG::la("Characteristics");LOG::die("0x%x", imageNTHeaders->FileHeader.Characteristics);
        LOG::la("Size of Optional Header");LOG::die("0x%x", imageNTHeaders->FileHeader.SizeOfOptionalHeader);
        LOG::la("Number of Symbols");LOG::die("0x%x", imageNTHeaders->FileHeader.NumberOfSymbols);
        // OPTIONAL_HEADER
        LOG::customText("OPTIONAL HEADER");

        LOG::la("Magic");LOG::die(" 0x%x  ", imageNTHeaders->OptionalHeader.Magic);
        LOG::la("Major Linker Version");LOG::die(" 0x%x  ", imageNTHeaders->OptionalHeader.MajorLinkerVersion);
        LOG::la("Minor Linker Version");LOG::die(" 0x%x  ", imageNTHeaders->OptionalHeader.MinorLinkerVersion);
        LOG::la("Size Of Code");LOG::die("0x%x", imageNTHeaders->OptionalHeader.SizeOfCode);
        LOG::la("Size Of Initialized Data");LOG::die(" 0x%x  ", imageNTHeaders->OptionalHeader.SizeOfInitializedData);
        LOG::la("Size Of UnInitialized Data");LOG::die(" 0x%x", imageNTHeaders->OptionalHeader.SizeOfUninitializedData);
        LOG::la("Address Of Entry Point (.text)");LOG::die(" 0x%x", imageNTHeaders->OptionalHeader.AddressOfEntryPoint);
        LOG::la("Base Of Code");LOG::die("0x%x", imageNTHeaders->OptionalHeader.BaseOfCode);
        LOG::la("Image Base");LOG::die("0x%x", imageNTHeaders->OptionalHeader.ImageBase);
        LOG::la("Section Alignment");LOG::die(" 0x%x", imageNTHeaders->OptionalHeader.SectionAlignment);
        LOG::la("File Alignmen");LOG::die("0x%x", imageNTHeaders->OptionalHeader.FileAlignment);

        LOG::la("Major Operating System Version");LOG::die("0x%x", imageNTHeaders->OptionalHeader.MajorOperatingSystemVersion);
        LOG::la("Minor Operating System Version");LOG::die("0x%x", imageNTHeaders->OptionalHeader.MinorOperatingSystemVersion);
        LOG::la("Major Image Version");LOG::die("0x%x", imageNTHeaders->OptionalHeader.MajorImageVersion);
        LOG::la("Minor Image Version");LOG::die("0x%x", imageNTHeaders->OptionalHeader.MinorImageVersion);
        LOG::la("Major Subsystem Version");LOG::die("0x%x", imageNTHeaders->OptionalHeader.MajorSubsystemVersion);
        LOG::la("Minor Subsystem Version");LOG::die("0x%x", imageNTHeaders->OptionalHeader.MinorSubsystemVersion);
        LOG::la("Win32 Version Value");LOG::die("0x%x", imageNTHeaders->OptionalHeader.Win32VersionValue);
        LOG::la("Size Of Image");LOG::die("0x%x", imageNTHeaders->OptionalHeader.SizeOfImage);
        LOG::la("Size Of Headers");LOG::die("0x%x", imageNTHeaders->OptionalHeader.SizeOfHeaders);
        LOG::la("CheckSum");LOG::die("0x%x", imageNTHeaders->OptionalHeader.CheckSum);
        LOG::la("Subsystem");LOG::die("0x%x", imageNTHeaders->OptionalHeader.Subsystem);
        LOG::la("DllCharacteristics");LOG::die("0x%x", imageNTHeaders->OptionalHeader.DllCharacteristics);
        LOG::la("Size Of Stack Reserve");LOG::die("0x%x", imageNTHeaders->OptionalHeader.SizeOfStackReserve);
        LOG::la("Size Of Stack Commit");LOG::die("0x%x", imageNTHeaders->OptionalHeader.SizeOfStackCommit);
        LOG::la("Size Of Heap Reserve");LOG::die("0x%x", imageNTHeaders->OptionalHeader.SizeOfHeapReserve);
        LOG::la("Size Of Heap Commit");LOG::die("0x%x", imageNTHeaders->OptionalHeader.SizeOfHeapCommit);
        LOG::la("Loader Flags");LOG::die("0x%x", imageNTHeaders->OptionalHeader.LoaderFlags);
        LOG::la("Number Of Rva And Sizes");LOG::die("0x%x", imageNTHeaders->OptionalHeader.NumberOfRvaAndSizes);

        // DATA_DIRECTORIES
        LOG::customText("DATA DIRECTORIES");
        LOG::la("Export Directory Address");LOG::die("0x%x; Size: 0x%x", imageNTHeaders->OptionalHeader.DataDirectory[0].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[0].Size);
        LOG::la("Import Directory Address");LOG::die("0x%x; Size: 0x%x", imageNTHeaders->OptionalHeader.DataDirectory[1].VirtualAddress, imageNTHeaders->OptionalHeader.DataDirectory[1].Size);
    }

    // get offset to first section headeer
    DWORD sectionLocation = (DWORD)imageNTHeaders + sizeof(DWORD) + (DWORD)(sizeof(IMAGE_FILE_HEADER)) + (DWORD)imageNTHeaders->FileHeader.SizeOfOptionalHeader;
    DWORD sectionSize = (DWORD)sizeof(IMAGE_SECTION_HEADER);

    // get offset to the import directory RVA
    DWORD importDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    // SECTION_HEADERS
    if(Sections)
        LOG::customText("SECTION HEADERS");
    // print section data
    for (int i = 0; i < imageNTHeaders->FileHeader.NumberOfSections; i++) {
        sectionHeader = (PIMAGE_SECTION_HEADER)sectionLocation;
        if(Sections){
            LOG::la("-> Section Name");LOG::die("%s", sectionHeader->Name);
            LOG::la("Virtual Size");LOG::die("0x%x", sectionHeader->Misc.VirtualSize);
            LOG::la("Virtual Address");LOG::die("0x%x", sectionHeader->VirtualAddress);
            LOG::la("Size Of Raw Data");LOG::die("0x%x", sectionHeader->SizeOfRawData);
            LOG::la("Pointer To Raw Data");LOG::die("0x%x", sectionHeader->PointerToRawData);
            LOG::la("Pointer To Relocations");LOG::die("0x%x", sectionHeader->PointerToRelocations);
            LOG::la("Pointer To Line Numbers");LOG::die("0x%x", sectionHeader->PointerToLinenumbers);
            LOG::la("Number Of Relocations");LOG::die("0x%x", sectionHeader->NumberOfRelocations);
            LOG::la("Number Of Line Numbers");LOG::die("0x%x", sectionHeader->NumberOfLinenumbers);
            LOG::la("Characteristics");LOG::die("0x%x", sectionHeader->Characteristics);
        }
        // save section that contains import directory table
        if (importDirectoryRVA >= sectionHeader->VirtualAddress && importDirectoryRVA < sectionHeader->VirtualAddress + sectionHeader->Misc.VirtualSize) {
            importSection = sectionHeader;
        }
        sectionLocation += sectionSize;
    }

    // get file offset to import table
    rawOffset = (DWORD)fileData + importSection->PointerToRawData;

    // get pointer to import descriptor's file offset. Note that the formula for calculating file offset is: imageBaseAddress + pointerToRawDataOfTheSectionContainingRVAofInterest + (RVAofInterest - SectionContainingRVAofInterest.VirtualAddress)
    importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rawOffset + (imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress - importSection->VirtualAddress));
    if(Imports)
        LOG::customText("DLL IMPORTS");
    for (; importDescriptor->Name != 0; importDescriptor++)	{
        // imported dll modules
        if(Imports){
            LOG::la("--> DLL File");LOG::die("%s",rawOffset + (importDescriptor->Name - importSection->VirtualAddress));
        }
        thunk = importDescriptor->OriginalFirstThunk == 0 ? importDescriptor->FirstThunk : importDescriptor->OriginalFirstThunk;
        thunkData = (PIMAGE_THUNK_DATA)(rawOffset + (thunk - importSection->VirtualAddress));

        // dll exported functions
        for (; thunkData->u1.AddressOfData != 0; thunkData++) {
            //a cheap and probably non-reliable way of checking if the function is imported via its ordinal number ¯\_(ツ)_/¯
            if(Imports){
                if (thunkData->u1.AddressOfData > 0x80000000) {
                    //show lower bits of the value to get the ordinal ¯\_(ツ)_/¯
                    LOG::die(" Ordinal: %x ", (WORD)thunkData->u1.AddressOfData);
                } else {
                    LOG::die(" -%s ", (rawOffset + (thunkData->u1.AddressOfData - importSection->VirtualAddress + 2)));
                }
            }
        }
    }
    LOG::SetColor(7);//white ...default color
    return 0;
}
