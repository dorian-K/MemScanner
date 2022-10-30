#pragma once

#include "MemScanner.h"

namespace MemScanner {
	class Mem {
	protected:
		MemScanner myScanner{};
	public:
		void startSigThread(){
			myScanner.startSigRunnerThread();
		}

		static std::pair<uint64_t, uint64_t> GetSectionRange(void* module, const char* name);
		template <bool forward>
		void* findSignature(const char* szSignature, bool enableCache = true, void* module = nullptr, const char* section = ".text");
	};
};
