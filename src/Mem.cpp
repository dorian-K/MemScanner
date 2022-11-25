#include "MemScanner/Mem.h"

#ifdef _WIN32
#include <psapi.h>
#include <windows.h>
#endif

namespace MemScanner {

#ifdef _WIN32

	std::pair<uint64_t, uint64_t> Mem::ResolveModuleSection(void *module, const char *section) {
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
		return {rangeStart, rangeEnd};
	}

	std::pair<uint64_t, uint64_t> Mem::GetSectionRange(void *module, const char *name) {
		auto baseAddr = reinterpret_cast<uint64_t>(module);
		auto *dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(module);
		if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) throw std::runtime_error("malformed dos header");

		auto *ntHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddr + dosHeader->e_lfanew);
		if (ntHeader->Signature != IMAGE_NT_SIGNATURE) throw std::runtime_error("malformed nt header");

		auto *sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
		for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++, sectionHeader++) {
			if (strncmp(name, reinterpret_cast<const char *>(sectionHeader->Name), 8) != 0) continue;
			return std::make_pair(baseAddr + sectionHeader->VirtualAddress, baseAddr + sectionHeader->VirtualAddress + sectionHeader->SizeOfRawData);
		}
		throw std::runtime_error("section not found");
	}

	template <bool forward>
	void *Mem::findSignature(const char *szSignature, bool enableCache, void *module, const char *section) {
		auto range = Mem::ResolveModuleSection(module, section);
		return myScanner.findSignatureInRange<forward>(szSignature, range.first, range.second, enableCache);
	}

	template <bool forward>
	void *Mem::findSignature(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, bool enableCache, void *module, const char *section) {
		auto range = Mem::ResolveModuleSection(module, section);
		return myScanner.findSignatureInRange<forward>(bytes, mask, range.first, range.second, enableCache);
	}

#else
	std::pair<uint64_t, uint64_t> Mem::GetSectionRange(void *module [[maybe_unused]], const char *name [[maybe_unused]]) {
		throw std::runtime_error("not implemented");
		return {};
	}
	template <bool forward>
	void *Mem::findSignature(const char *szSignature [[maybe_unused]], bool enableCache [[maybe_unused]], void *module [[maybe_unused]],
							 const char *section [[maybe_unused]]) {
		throw std::runtime_error("not implemented");
		return {};
	}

	template <bool forward>
	void *Mem::findSignature(const std::vector<uint8_t> &bytes [[maybe_unused]], const std::vector<uint8_t> &mask [[maybe_unused]],
							 bool enableCache [[maybe_unused]], void *module [[maybe_unused]], const char *section [[maybe_unused]]) {
		throw std::runtime_error("not implemented");
		return {};
	}

	std::pair<uint64_t, uint64_t> Mem::ResolveModuleSection(void *module, const char *m) { return {}; }

#endif

	template void *Mem::findSignature<true>(const char *, bool, void *, const char *);

	template void *Mem::findSignature<false>(const char *, bool, void *, const char *);

	template void *Mem::findSignature<true>(const std::vector<uint8_t> &, const std::vector<uint8_t> &, bool, void *, const char *);

	template void *Mem::findSignature<false>(const std::vector<uint8_t> &, const std::vector<uint8_t> &, bool, void *, const char *);
}  // namespace MemScanner