#include "global.h"

char* Utils::Compare(const char* haystack, const char* needle)
{
	do
	{
		const char* h = haystack;
		const char* n = needle;
		while (tolower(static_cast<unsigned char>(*h)) == tolower(static_cast<unsigned char>(*n)) && *n)
		{
			h++;
			n++;
		}

		if (*n == 0)
			return const_cast<char*>(haystack);
	} while (*haystack++);
	return nullptr;
}

PVOID Utils::GetModuleBase(const char* moduleName)
{
	PVOID address = nullptr;
	ULONG size = 0;

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &size, 0, &size);
	if (status != STATUS_INFO_LENGTH_MISMATCH)
		return nullptr;

#pragma warning(disable : 4996) // 'ExAllocatePool': ExAllocatePool is deprecated, use ExAllocatePool2
	PSYSTEM_MODULE_INFORMATION moduleList = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, size));
	if (!moduleList)
		return nullptr;

	status = ZwQuerySystemInformation(SystemModuleInformation, moduleList, size, nullptr);
	if (!NT_SUCCESS(status))
		goto end;

	for (ULONG_PTR i = 0; i < moduleList->ulModuleCount; i++)
	{
		ULONG64 pointer = reinterpret_cast<ULONG64>(&moduleList->Modules[i]);
		pointer += sizeof(SYSTEM_MODULE);
		if (pointer > (reinterpret_cast<ULONG64>(moduleList) + size))
			break;

		SYSTEM_MODULE module = moduleList->Modules[i];
		module.ImageName[255] = '\0';
		if (Compare(module.ImageName, moduleName))
		{
			address = module.Base;
			break;
		}
	}

end:
	ExFreePool(moduleList);
	return address;
}

#define IN_RANGE(x, a, b) (x >= a && x <= b)
#define GET_BITS(x) (IN_RANGE((x&(~0x20)),'A','F')?((x&(~0x20))-'A'+0xA):(IN_RANGE(x,'0','9')?x-'0':0))
#define GET_BYTE(a, b) (GET_BITS(a) << 4 | GET_BITS(b))
ULONG64 Utils::FindPattern(void* baseAddress, ULONG64 size, const char* pattern)
{
	BYTE* firstMatch = nullptr;
	const char* currentPattern = pattern;

	BYTE* start = static_cast<BYTE*>(baseAddress);
	BYTE* end = start + size;

	for (BYTE* current = start; current < end; current++)
	{
		BYTE byte = currentPattern[0]; if (!byte) return reinterpret_cast<ULONG64>(firstMatch);
		if (byte == '\?' || *static_cast<BYTE*>(current) == GET_BYTE(byte, currentPattern[1]))
		{
			if (!firstMatch) firstMatch = current;
			if (!currentPattern[2]) return reinterpret_cast<ULONG64>(firstMatch);
			((byte == '\?') ? (currentPattern += 2) : (currentPattern += 3));
		}
		else
		{
			currentPattern = pattern;
			firstMatch = nullptr;
		}
	}

	return 0;
}

ULONG64 Utils::FindPatternImage(void* base, const char* pattern)
{
	ULONG64 match = 0;

	PIMAGE_NT_HEADERS64 headers = reinterpret_cast<PIMAGE_NT_HEADERS64>(reinterpret_cast<ULONG64>(base) + static_cast<PIMAGE_DOS_HEADER>(base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (USHORT i = 0; i < headers->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, ".text", 5) == 0 || *reinterpret_cast<DWORD32*>(section->Name) == 'EGAP')
		{
			match = FindPattern(reinterpret_cast<void*>(reinterpret_cast<ULONG64>(base) + section->VirtualAddress), section->Misc.VirtualSize, pattern);
			if (match)
				break;
		}
	}

	return match;
}

SIZE_T Utils::MemoryCopySafe(void* destination, void* source, SIZE_T size)
{
	MM_COPY_ADDRESS address;
	address.VirtualAddress = source;
	SIZE_T copied;
	MmCopyMemory(destination, address, size, MM_COPY_MEMORY_VIRTUAL, &copied);
	return copied;
}

SIZE_T Utils::GetFunctionSize(ULONG64 function)
{
	constexpr SIZE_T sizeToCheck = 2000;
	PBYTE buffer = static_cast<PBYTE>(ExAllocatePool(NonPagedPool, sizeToCheck));
	if (!buffer)
		return 0;

	MemoryCopySafe(buffer, reinterpret_cast<void*>(function), sizeToCheck);

	for (SIZE_T i = 0; i < sizeToCheck; i++)
	{
		BYTE current = buffer[i];
		if (current == 0xC3)
		{
			ExFreePool(buffer);
			return i;
		}
	}

	ExFreePool(buffer);
	return 0;
}

bool Utils::IsInRange(ULONG64 start, SIZE_T size, ULONG64 input)
{
	return (input > start && input < start + size);
}

void Utils::ChangeIoc(PIO_STACK_LOCATION ioc, PIRP irp, PIO_COMPLETION_ROUTINE routine)
{
	PIOC_REQUEST request = static_cast<PIOC_REQUEST>(ExAllocatePool(NonPagedPool, sizeof(IOC_REQUEST)));

	request->Buffer = irp->AssociatedIrp.SystemBuffer;
	request->Size = ioc->Parameters.DeviceIoControl.OutputBufferLength;
	request->OriginalContext = ioc->Context;
	request->Original = ioc->CompletionRoutine;

	ioc->Control = SL_INVOKE_ON_SUCCESS;
	ioc->Context = request;
	ioc->CompletionRoutine = routine;
}

UINT32 Utils::BigEndianToLittleEndian32(UINT32 bigEndianValue)
{
	return ((bigEndianValue >> 24) & 0x000000FF) |
		((bigEndianValue >> 8) & 0x0000FF00) |
		((bigEndianValue << 8) & 0x00FF0000) |
		((bigEndianValue << 24) & 0xFF000000);
}

USHORT Utils::BigEndianToLittleEndian16(USHORT bigEndianValue)
{
	return ((bigEndianValue >> 8) & 0x00FF) |
		((bigEndianValue << 8) & 0xFF00);
}

NTSTATUS Utils::GenerateRandomKey(TPM2B_PUBLIC_KEY_RSA* inputKey)
{
    // Example 2048-bit modulus (replace this with your actual desired static modulus if you wish)
    static const BYTE staticRsaKey[256] = {
        // This is a sample RSA 2048-bit modulus. Replace with your own if desired.
        0xB9,0x3E,0xC6,0x94,0xE2,0x7B,0x7A,0x9D,0x5E,0xC4,0x45,0x3D,0x4D,0x8B,0x7B,0x7D,
        0xF5,0x65,0x23,0xF9,0x6B,0x71,0x6D,0x32,0xA8,0x75,0xE5,0xD5,0x94,0xF8,0x7E,0xD2,
        0x6E,0x19,0x8B,0xB1,0x04,0x91,0x01,0x59,0x8A,0x16,0x3C,0x0F,0x51,0xC9,0xC2,0x40,
        0x39,0xC3,0xDA,0xDF,0x2A,0xC5,0x23,0xA3,0xF4,0x1E,0x7D,0xA7,0x24,0x14,0xB5,0xA3,
        0x6C,0x09,0xAF,0xF7,0x1A,0x56,0xA6,0x67,0xB9,0xB9,0x17,0x5B,0x25,0x7B,0x8D,0x6E,
        0x2A,0xC9,0x4A,0x5B,0x19,0x02,0xB2,0xA2,0xE3,0x46,0x8A,0x63,0x12,0x00,0xB3,0xCD,
        0xC8,0xD6,0x27,0x2C,0x82,0x8A,0xC2,0x7A,0xA6,0xC0,0x1D,0x85,0x3E,0xDE,0x24,0x68,
        0x5C,0xA3,0xA6,0xD7,0x3E,0xAB,0x14,0x03,0xB1,0xDF,0xB5,0x13,0xC6,0xEF,0x09,0xEA,
        0x6B,0xB9,0x45,0x5D,0x5C,0xC8,0xDF,0x71,0x89,0x7B,0x12,0x87,0x4A,0xD5,0x21,0xA4,
        0x16,0xA3,0x9B,0x5D,0x1C,0x9A,0x07,0xDB,0x83,0x9C,0x1B,0x95,0x54,0xA0,0x1D,0xD9,
        0xF2,0x9B,0xA3,0xE4,0x31,0x38,0x3A,0x8A,0x36,0x64,0x56,0x49,0xD5,0x9A,0x77,0xAC,
        0xFD,0x43,0x56,0xB6,0x2A,0xB3,0xA9,0x48,0xC1,0x58,0xB5,0x3C,0x54,0xA8,0x65,0x4B,
        0x6C,0x16,0xB6,0x8C,0xF1,0x8F,0x64,0xBE,0xCD,0xE7,0x51,0x85,0x52,0xCA,0xE7,0xC6,
        0x7A,0xC8,0xA3,0x37,0x44,0x0B,0x2B,0x1B,0x6C,0xE9,0x74,0xAD,0xA4,0xD3,0x31,0xF4,
        0xF9,0xD1,0xA3,0x34,0x5A,0xD8,0xD9,0x88,0x7F,0x19,0xD1,0x60,0xE9,0x72,0x4A,0xE2,
        0x9A,0x70,0xE1,0x8C,0x6D,0xD4,0x2E,0x46,0x4A,0xB3,0x5C,0xA7,0x53,0x43,0x2E,0xB1
    };

    memcpy(inputKey->buffer, staticRsaKey, sizeof(staticRsaKey));
    inputKey->size = static_cast<UINT16>(sizeof(staticRsaKey));
    return STATUS_SUCCESS;
}
