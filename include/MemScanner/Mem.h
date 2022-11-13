#pragma once

#include "MemScanner.h"

namespace MemScanner {
	class Mem {
	protected:
		MemScanner myScanner{};

		static std::pair<uint64_t, uint64_t> ResolveModuleSection(void* module, const char* section);
	public:
		void startSigThread(){
			myScanner.startSigRunnerThread();
		}
		void stopSigThread(){
			myScanner.stopSigRunnerThread();
		}

		MemScanner& getScanner(){
			return this->myScanner;
		}

		static std::pair<uint64_t, uint64_t> GetSectionRange(void* module, const char* name);
		template <bool forward>
		void* FindSignature(const char* szSignature, bool enableCache = true, void* module = nullptr, const char* section = ".text");
		template <bool forward>
		void* FindSignature(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& mask,
							bool enableCache = true, void* module = nullptr, const char* section = ".text");
	};
};
