#pragma once

#include "MemScanner.h"

namespace MemScanner {
	class Mem {
	public:
		static std::pair<uint64_t, uint64_t> GetSectionRange(void* module, const char* name);
		template <bool forward>
		static void* FindSignature(const char* szSignature, bool enableCache = true, void* module = nullptr, const char* section = ".text");
	};

	extern MemScanner gMemScanner;
};
