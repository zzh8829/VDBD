#include <fstream>
#include <iostream>
#include <streambuf>
#include <sstream>
#include <cctype>
#include <cassert>
#include <vector>
#include "windows/winnt.h"

using namespace std;

void decompile_win(stringstream& data)
{
	IMAGE_DOS_HEADER dosHeader;

	data.read((char*)&dosHeader, sizeof(IMAGE_DOS_HEADER));

	assert(dosHeader.e_magic == IMAGE_DOS_SIGNATURE);

#define _DEBUG 1
#if _DEBUG
	cout << "Image Dos Header " << hex << sizeof(IMAGE_DOS_HEADER) << endl
		<< 	"e_magic " << dosHeader.e_magic << endl
		<< 	"e_cblp " << dosHeader.e_cblp << endl
		<< 	"e_cp " << dosHeader.e_cp << endl
		<< 	"e_crlc " << dosHeader.e_crlc << endl
		<< 	"e_cparhdr " << dosHeader.e_cparhdr << endl
		<< 	"e_minalloc " << dosHeader.e_minalloc << endl
		<< 	"e_maxalloc " << dosHeader.e_maxalloc << endl
		<< 	"e_ss " << dosHeader.e_ss << endl
		<< 	"e_sp " << dosHeader.e_sp << endl
		<< 	"e_csum " << dosHeader.e_csum << endl
		<< 	"e_ip " << dosHeader.e_ip << endl
		<< 	"e_cs " << dosHeader.e_cs << endl
		<< 	"e_lfarlc " << dosHeader.e_lfarlc << endl
		<< 	"e_ovno " << dosHeader.e_ovno << endl
		// 	"e_res[4] " << dosHeader.e_res[4] << endl
		<< 	"e_oemid " << dosHeader.e_oemid << endl
		<< 	"e_oeminfo " << dosHeader.e_oeminfo << endl
		// 	"e_res2[10] " << dosHeader.e_res2[10] << endl
		<< 	"e_lfanew " << dosHeader.e_lfanew << endl
		<< endl;
#endif

	data.seekg(dosHeader.e_lfanew, ios::beg);

	uint32_t signature;
	data.read((char*)&signature, sizeof(uint32_t));

	assert(signature == IMAGE_NT_SIGNATURE);

#if _DEBUG
	cout << "signature " << signature << endl
		<< endl;
#endif

	IMAGE_FILE_HEADER fileHeader;
	data.read((char*)&fileHeader, sizeof(IMAGE_FILE_HEADER));

#if _DEBUG
	cout << "Image File Header" << endl
		<< "Machine " << fileHeader.Machine << endl
		<< "NumberOfSections " << fileHeader.NumberOfSections << endl
		<< "TimeDateStamp " << fileHeader.TimeDateStamp << endl
		<< "PointerToSymbolTable " << fileHeader.PointerToSymbolTable << endl
		<< "NumberOfSymbols " << fileHeader.NumberOfSymbols << endl
		<< "SizeOfOptionalHeader " << fileHeader.SizeOfOptionalHeader << endl
		<< "Characteristics " << fileHeader.Characteristics << endl
		<< endl;
#endif

	uint16_t optionalHeaderMagic;
	data.read((char*)&optionalHeaderMagic, sizeof(uint16_t));
	data.seekg(-(int)sizeof(uint16_t), ios::cur); // unread magic

	if(optionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
			IMAGE_OPTIONAL_HEADER32 optionalHeader;
			data.read((char*)&optionalHeader, sizeof(IMAGE_OPTIONAL_HEADER32));

#if _DEBUG
			cout << "Image Optional Header 32 " << sizeof(IMAGE_OPTIONAL_HEADER32) << endl
				<< "Magic " << optionalHeader.Magic << endl
				<< "MajorLinkerVersion " << optionalHeader.MajorLinkerVersion << endl
				<< "MinorLinkerVersion " << optionalHeader.MinorLinkerVersion << endl
				<< "SizeOfCode " << optionalHeader.SizeOfCode << endl
				<< "SizeOfInitializedData " << optionalHeader.SizeOfInitializedData << endl
				<< "SizeOfUninitializedData " << optionalHeader.SizeOfUninitializedData << endl
				<< "AddressOfEntryPoint " << optionalHeader.AddressOfEntryPoint << endl
				<< "BaseOfCode " << optionalHeader.BaseOfCode << endl
				<< "BaseOfData " << optionalHeader.BaseOfData << endl
				<< "ImageBase " << optionalHeader.ImageBase << endl
				<< "SectionAlignment " << optionalHeader.SectionAlignment << endl
				<< "FileAlignment " << optionalHeader.FileAlignment << endl
				<< "MajorOperatingSystemVersion " << optionalHeader.MajorOperatingSystemVersion << endl
				<< "MinorOperatingSystemVersion " << optionalHeader.MinorOperatingSystemVersion << endl
				<< "MajorImageVersion " << optionalHeader.MajorImageVersion << endl
				<< "MinorImageVersion " << optionalHeader.MinorImageVersion << endl
				<< "MajorSubsystemVersion " << optionalHeader.MajorSubsystemVersion << endl
				<< "MinorSubsystemVersion " << optionalHeader.MinorSubsystemVersion << endl
				<< "Win32VersionValue " << optionalHeader.Win32VersionValue << endl
				<< "SizeOfImage " << optionalHeader.SizeOfImage << endl
				<< "SizeOfHeaders " << optionalHeader.SizeOfHeaders << endl
				<< "CheckSum " << optionalHeader.CheckSum << endl
				<< "Subsystem " << optionalHeader.Subsystem << endl
				<< "DllCharacteristics " << optionalHeader.DllCharacteristics << endl
				<< "SizeOfStackReserve " << optionalHeader.SizeOfStackReserve << endl
				<< "SizeOfStackCommit " << optionalHeader.SizeOfStackCommit << endl
				<< "SizeOfHeapReserve " << optionalHeader.SizeOfHeapReserve << endl
				<< "SizeOfHeapCommit " << optionalHeader.SizeOfHeapCommit << endl
				<< "LoaderFlags " << optionalHeader.LoaderFlags << endl
				<< "NumberOfRvaAndSizes " << optionalHeader.NumberOfRvaAndSizes << endl
				<< endl;

#endif

		vector<IMAGE_SECTION_HEADER> sectionHeaders;
		for(int i=0;i < fileHeader.NumberOfSections;i++)
		{
			IMAGE_SECTION_HEADER sectionHeader;
			data.read((char*)&sectionHeader, sizeof(IMAGE_SECTION_HEADER));

#if _DEBUG
			cout << "Image Section Header " << sizeof(IMAGE_SECTION_HEADER) << endl
				<< "Name " << sectionHeader.Name << endl
				<< "PhysicalAddress " << sectionHeader.PhysicalAddress << endl
				<< "VirtualSize " << sectionHeader.VirtualSize << endl
				<< "VirtualAddress " << sectionHeader.VirtualAddress << endl
				<< "SizeOfRawData " << sectionHeader.SizeOfRawData << endl
				<< "PointerToRawData " << sectionHeader.PointerToRawData << endl
				<< "PointerToRelocations " << sectionHeader.PointerToRelocations << endl
				<< "PointerToLinenumbers " << sectionHeader.PointerToLinenumbers << endl
				<< "NumberOfRelocations " << sectionHeader.NumberOfRelocations << endl
				<< "NumberOfLinenumbers " << sectionHeader.NumberOfLinenumbers << endl
				<< "Characteristics " << sectionHeader.Characteristics << endl
				<< endl;
#endif
		}

	}
	else if(optionalHeaderMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{

	}

	cout << "Unknown:" << endl;
	for(int i=0;i!=1000;i++)
	{
		char byte;
		data >> byte;
		cout << (int)byte << " ";
	}
	cout << endl;
	cout << "END" << endl;
}

void decompile_osx(stringstream& data)
{

}

int main(int argc, char* argv[])
{
	//string binary = "./samples/helloworld/helloworld-win-mingw.exe";
	string filename = "./samples/helloworld/helloworld-osx-gcc";

	if(argc > 1)
	{
		if(argc > 2)
		{
			cerr << "Usage: " << argv[0] << " [filename]" << endl;
			exit(1);
		}
		filename = argv[1];
	}
	//freopen("vdbd.out", "w", stdout);

	ifstream file;
	file.open(filename, ios::binary);

	if(!file.is_open())
	{
		cerr << "Cannot open file: " << filename << endl;
		exit(1);
	}

    stringstream data;
    copy(istreambuf_iterator<char>(file),
    	istreambuf_iterator<char>(),
    	ostreambuf_iterator<char>(data));

    file.close();

    decompile_osx(data);
    //decompile_win(data);

	return 0;
}
