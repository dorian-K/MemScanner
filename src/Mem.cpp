#include "MemScanner/Mem.h"

#include <windows.h>
#include <psapi.h>

namespace MemScanner {

	std::pair<uint64_t, uint64_t> Mem::GetSectionRange(void *module, const char *name) {
		auto baseAddr = reinterpret_cast<uint64_t>(module);
		auto *dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			throw std::runtime_error("malformed dos header");

		auto *ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddr + dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
			throw std::runtime_error("malformed nt header");

		auto *sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, sectionHeader++) {
			if (strncmp(name, reinterpret_cast<const char *>(sectionHeader->Name), 8) != 0)
				continue;
			return std::make_pair(baseAddr + sectionHeader->VirtualAddress,
								  baseAddr + sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData);
		}
		throw std::runtime_error("section not found");
	}

	template<bool forward>
	void *Mem::FindSignature(const char *szSignature, bool enableCache, void *module, const char *section) {
		static auto ExeHandle = (void *) GetModuleHandleA(nullptr);
		static MODULEINFO miModInfo;
		static std::pair<uint64_t, uint64_t> ExeTextSection;
		static bool init = false;
		if (!init) {
			GetModuleInformation(GetCurrentProcess(), (HMODULE) ExeHandle, &miModInfo, sizeof(MODULEINFO));
			ExeTextSection = GetSectionRange(ExeHandle, ".text");
			init = true;
		}
		uintptr_t rangeStart, rangeEnd;
		if (module == nullptr) {
			if (section == nullptr || *section == 0) {
				// Entire module
				rangeStart = (uintptr_t) ExeHandle;
				rangeEnd = rangeStart + miModInfo.SizeOfImage;
			} else if (strcmp(section, ".text") == 0) {
				rangeStart = ExeTextSection.first;
				rangeEnd = ExeTextSection.second;
			} else {
				auto mySection = GetSectionRange(ExeHandle, section);
				rangeStart = mySection.first;
				rangeEnd = mySection.second;
			}
		} else {
			if (section == nullptr || *section == 0) {
				rangeStart = (uintptr_t) module;
				MODULEINFO customModInfo{};
				GetModuleInformation(GetCurrentProcess(), (HMODULE) module, &customModInfo, sizeof(MODULEINFO));
				rangeEnd = rangeStart + customModInfo.SizeOfImage;
			} else {
				auto mySection = GetSectionRange(module, section);
				rangeStart = mySection.first;
				rangeEnd = mySection.second;
			}
		}
		//dprnt("ranges: {} - {}; {} - {}", (void*)rangeStart, (void*)rangeEnd, (void*)ExeHandle, (void*)((uintptr_t)ExeHandle + miModInfo.SizeOfImage));

		return gMemScanner.findSignatureInRange<forward>(szSignature, rangeStart, rangeEnd, enableCache);
	}


	template void *Mem::FindSignature<true>(const char *, bool, void *, const char *);

	template void *Mem::FindSignature<false>(const char *, bool, void *, const char *);

	MemScanner gMemScanner;

}