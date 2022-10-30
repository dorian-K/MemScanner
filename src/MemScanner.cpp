#include "MemScanner.h"

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
// clang-format off
#include <windows.h>
#include <psapi.h>
// clang-format on
#include <immintrin.h>

#ifndef _XCR_XFEATURE_ENABLED_MASK
#define _XCR_XFEATURE_ENABLED_MASK 0
#endif

#ifdef __cplusplus
#if defined(_MSVC_LANG) && _MSVC_LANG > __cplusplus
#define _STL_LANG _MSVC_LANG
#else  // ^^^ language mode is _MSVC_LANG / language mode is __cplusplus vvv
#define _STL_LANG __cplusplus
#endif // ^^^ language mode is larger of _MSVC_LANG and __cplusplus ^^^
#else  // ^^^ determine compiler's C++ mode / no C++ support vvv
#define _STL_LANG 0L
#endif // ^^^ no C++ support ^^^

#ifndef _HAS_CXX20
#if _HAS_CXX17 && _STL_LANG > 201703L
#define _HAS_CXX20 1
#else
#define _HAS_CXX20 0
#endif
#endif // _HAS_CXX20

#undef _STL_LANG

#ifndef MEM_LIKELY
#if _HAS_CXX20
#define MEM_LIKELY [[likely]]
#define MEM_UNLIKELY [[unlikely]]
#else
#define MEM_LIKELY
#define MEM_UNLIKELY
#endif
#endif

void MemScanner::addToSearchMap(const std::vector<unsigned char>& bytes, const std::vector<unsigned char>& mask, uintptr_t start, uintptr_t end) {
	if (bytes.size() > 8) return;
	SearchMapKey key(bytes, mask);
	SearchMapValue val = {start, end};
	std::lock_guard lock(searchMapMutex);
	if (searchMap.size() > 2000) return;
	searchMap[key] = val;
}

bool MemScanner::findInSearchMap(const SearchMapKey& key, SearchMapValue& region, bool allowAdd, SearchMapValue& originalRegion) {
	std::shared_lock lock(searchMapMutex);

	auto res = searchMap.find(key);
	if (res == searchMap.end()) {
		if (allowAdd) {
			lock.unlock();
			std::lock_guard g(needSearchMutex);
			if (needSearchMap.size() < 200) {
				for (const auto& [prio, entr] : needSearchMap)
					if (entr.key == key) return false;	// already in needSearchMap
				needSearchMap.insert({0, {key, false, originalRegion}});
			}
		}
		return false;
	}

	auto& val = res->second;
	region.start = std::max(region.start, val.start);
	region.end = std::min(region.end, val.end);

	return true;
}

void MemScanner::getOrAddToSearchMap8Byte(const unsigned char* bytes, const unsigned char* mask, int size, SearchMapValue& region, bool allowAdd, SearchMapValue& originalRegion) {
	// iprnt("prev region: {:X} - {:X}", region.start, region.end);

	for (int i = 0; i < std::min(8, size); i++) {
		if (i > 0 && mask[i] == 0) continue;

		SearchMapKey key(bytes, mask, i + 1);
		if (!findInSearchMap(key, region, allowAdd, originalRegion)) continue;
		if (region.start > region.end) return;
	}
	region.end += size;
	// iprnt("now region: {:X} - {:X}", region.start, region.end);
}

void MemScanner::getOrAddToSearchMap(const std::vector<unsigned char>& bytes, const std::vector<unsigned char>& mask, SearchMapValue& region, bool allowAdd) {
	SearchMapValue originalRegion = region;
	originalRegion.end += bytes.size();
	getOrAddToSearchMap8Byte(bytes.data(), mask.data(), (int) bytes.size(), region, allowAdd, originalRegion);
	if (bytes.size() <= 8 || region.start >= region.end) return;
	region.end -= bytes.size();

	// try all the permutations
	for (int i = 1; i < bytes.size(); i++) {
		if (mask[i] == 0) continue;
		SearchMapValue tempRegion = {region.start, region.end};
		getOrAddToSearchMap8Byte(bytes.data() + i, mask.data() + i, (int) bytes.size() - i, tempRegion, allowAdd, originalRegion);
		region.start = std::max(region.start, tempRegion.start - i);
	}

	region.end += bytes.size();
}

MemScanner::~MemScanner() {
	this->stopSigRunnerThread();
}

bool hasAvxOSSupport(){
	// http://stackoverflow.com/a/22521619/922184
	bool avxSupported = false;

	int cpuInfo[4];
	__cpuidex(cpuInfo, 1, 0);

	bool osUsesXSAVE_XRSTORE = (cpuInfo[2] & (1 << 27)) != 0;
	bool cpuAVXSupport = (cpuInfo[2] & (1 << 28)) != 0;

	if (osUsesXSAVE_XRSTORE && cpuAVXSupport)
	{
		uint64_t xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
		avxSupported = (xcrFeatureMask & 0x6) == 0x6;
	}

	return avxSupported;
}

bool MemScanner::hasFullAVXSupport() {
	static int cached = -1;
	if (cached != -1)
		return cached == 1;

	// OS Support
	if (!hasAvxOSSupport()) {
		cached = 0;
		return false;
	}
	// CPU support - https://github.com/Mysticial/FeatureDetector/blob/master/src/x86/cpu_x86.cpp#L109
	bool avx, avx2;
	int info[4];
	__cpuidex(info, 0, 0);
	int nIds = info[0];

	if (nIds >= 0x00000001) {
		__cpuidex(info, 0x00000001, 0);

		avx = (info[2] & ((int) 1 << 28)) != 0;
	}
	if (nIds >= 0x00000007) {
		__cpuidex(info, 0x00000007, 0);
		avx2 = (info[1] & ((int) 1 << 5)) != 0;
	}

	if(avx && avx2){
		cached = 1;
		return true;
	}else{
		cached = 0;
		return false;
	}
}

bool MemScanner::doSearchSingleMapKey() {

	SearchMapKey key;
	SearchMapValue regionToBeSearched{};
	{
		std::lock_guard g(needSearchMutex);
		if (needSearchMap.empty()) return false;

		auto iter = needSearchMap.begin();
		while (iter != needSearchMap.end() && iter->second.isInSearch) iter++;

		if (iter == needSearchMap.end()) return false;

		iter->second.isInSearch = true;

		key = iter->second.key;
		regionToBeSearched = iter->second.regionToBeSearched;
	}

	SearchMapValue val = {regionToBeSearched.start, regionToBeSearched.end - key.numBytesUsed};
	std::vector<unsigned char> bytes(key.bytes, &key.bytes[key.numBytesUsed]);
	std::vector<unsigned char> mask(key.mask, &key.mask[key.numBytesUsed]);
	getOrAddToSearchMap(bytes, mask, val, false);
	if (val.start > val.end) goto end;

	{
		//uintptr_t prevSearchSpace = val.end - val.start;
		auto start = reinterpret_cast<uintptr_t>(MemScanner::findSignatureFast32<true>(bytes, mask, val.start, val.end));
		if (start == 0) {
			val.start = val.end;
		} else {
			val.start = start;
			// iprnt("reduced search space to {:X} prev: {:X} diff: {:X}", val.end - val.start, prevSearchSpace, prevSearchSpace - (val.end - val.start));
		}
		addToSearchMap(bytes, mask, val.start, val.end);
	}

end:
	std::lock_guard g(needSearchMutex);
	auto iter = needSearchMap.begin();
	while (iter != needSearchMap.end() && iter->second.key != key) iter++;
	if (iter == needSearchMap.end()) {
		//dprnt("Key not found back in map!");
		return true;
	}
	needSearchMap.erase(iter);
	return true;
}

template <bool forward>
void* MemScanner::findSignatureFast1(const std::vector<unsigned char>& bytes, const std::vector<unsigned char>& mask, uintptr_t rangeStart,
									 uintptr_t rangeEnd) {
	const int patternSize = (int) mask.size();
	if (patternSize < 1) MEM_UNLIKELY
		__debugbreak();
	if (rangeStart + bytes.size() > rangeEnd) MEM_UNLIKELY
		return nullptr;
	auto* maskStart = mask.data();
	auto* bytesStart = bytes.data();
	auto startByte = reinterpret_cast<const unsigned char*>(bytesStart)[0];
	auto startMask = reinterpret_cast<const unsigned char*>(maskStart)[0];
	if (startMask == 0) MEM_UNLIKELY
		__debugbreak();
	const auto end = rangeEnd - patternSize;

	for (uintptr_t pCur = forward ? rangeStart : end; forward ? (pCur <= end) : (pCur >= rangeStart); pCur += (forward ? 1 : -1)) {
		if (*reinterpret_cast<unsigned char*>(pCur) == startByte) MEM_UNLIKELY {
			uintptr_t curP = pCur + 1;
			int off = 1;

			for (; off < patternSize; off++) {
				if (*(unsigned char*) curP != bytesStart[off] && maskStart[off] != 0) MEM_LIKELY
					break;
				curP++;
			}
			if (off == patternSize) MEM_UNLIKELY
				return reinterpret_cast<void*>(pCur);
		}
	}

	return nullptr;
}

template <bool forward>
void* MemScanner::findSignatureFast8(const std::vector<unsigned char>& bytes, const std::vector<unsigned char>& mask, uintptr_t rangeStart, uintptr_t rangeEnd) {
	const int patternSize = (int) mask.size();
	if (!forward || patternSize < 8) return this->findSignatureFast1<forward>(bytes, mask, rangeStart, rangeEnd);
	if (rangeStart + bytes.size() > rangeEnd) MEM_UNLIKELY
		return nullptr;

	const auto* maskStart = mask.data();
	const auto startMask = reinterpret_cast<const unsigned __int64*>(maskStart)[0];

	if (startMask != 0xFFFFFFFFFFFFFFFFui64) MEM_LIKELY // 1 Byte scan is more efficient with a mask
		return this->findSignatureFast1<forward>(bytes, mask, rangeStart, rangeEnd);

	const auto* bytesStart = bytes.data();
	const auto startByte = reinterpret_cast<const unsigned __int64*>(bytesStart)[0];
	const auto end = rangeEnd - patternSize;

	for (uintptr_t pCur = rangeStart; pCur <= end; pCur++) {
		if (*reinterpret_cast<unsigned __int64*>(pCur) == startByte) MEM_UNLIKELY {
			uintptr_t curP = pCur + 8;
			int off = 8;

			for (; off < patternSize; off++) {
				if (*(unsigned char*) curP != bytesStart[off] && maskStart[off] != 0) MEM_LIKELY
					break;
				curP++;
			}
			if (off == patternSize) MEM_UNLIKELY
				return reinterpret_cast<void*>(pCur);
		}
	}

	return nullptr;
}

template <bool forward>
void* MemScanner::findSignatureFast32(const std::vector<unsigned char>& bytes, const std::vector<unsigned char>& mask, uintptr_t rangeStart, uintptr_t rangeEnd) {
	const int patternSize = (int) mask.size();
	if (patternSize <= 1 || !forward) return this->findSignatureFast1<forward>(bytes, mask, rangeStart, rangeEnd);
	if(!MemScanner::hasFullAVXSupport()) return this->findSignatureFast8<true>(bytes, mask, rangeStart, rangeEnd);
	if (rangeStart + std::max((size_t)32, bytes.size()) > rangeEnd) MEM_UNLIKELY
		return nullptr;

	const __m256i firstByteLaidOut = _mm256_set1_epi8(*reinterpret_cast<const char*>(&bytes[0])); // AVX

	const auto* maskStart = mask.data();
	const auto* bytesStart = bytes.data();
	const auto end = rangeEnd - std::max(32, patternSize);

	for (uintptr_t pCur = rangeStart; pCur <= end; pCur += 32) {
		//const __m256i toBeCompared = _mm256_loadu_epi8(reinterpret_cast<__m256i*>(pCur)); // AVX-512, but msvc compiles it to vmovdqu anyways??
		const __m256i toBeCompared = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(pCur)); // AVX
		//unsigned int matches = _mm256_cmpeq_epi8_mask(toBeCompared, firstByteLaidOut); // AVX-512
		const __m256i cmp = _mm256_cmpeq_epi8(toBeCompared, firstByteLaidOut); // AVX2
		unsigned int matches = _mm256_movemask_epi8(cmp); // AVX2
		if(matches == 0)
			continue;

		do{
			unsigned long curBit = 0;
			_BitScanForward(&curBit, matches);

			uintptr_t curP = pCur + curBit + 1;
			int off = 1;

			for (; off < patternSize; off++) {
				if (*(unsigned char*) curP != bytesStart[off] && maskStart[off] != 0) MEM_LIKELY
					break;
				curP++;
			}
			if (off >= patternSize) MEM_UNLIKELY return reinterpret_cast<void*>(pCur + curBit);

			matches = _blsr_u32(matches);
		}while(matches);
	}

	if(patternSize < 32){ // Scan the remaining 32 bytes with the old algorithm
		return this->findSignatureFast1<true>(bytes, mask, end - 1, rangeEnd);
	}

	return nullptr;
}

template <bool forward>
void* MemScanner::findSignatureInRange(const char* szSignature, uintptr_t start, uintptr_t end, bool enableCache, bool allowAddToCache) {
	std::vector<unsigned char> patternBytes;
	patternBytes.reserve(strlen(szSignature) / 3 + 1);
	std::vector<unsigned char> patternMask;
	patternMask.reserve(strlen(szSignature) / 3 + 1);

	for (const char* patIt = szSignature; *patIt;) {
		while (*patIt == ' ') patIt++;

		if (!*patIt) break;

		if (*patIt == '\?') {
			if (!patternMask.empty()) {
				patternBytes.push_back(0);
				patternMask.push_back(0);
			}

			patIt++;
			while (*patIt == '\?') patIt++;
			continue;
		}

		if (!*(patIt + 1)) throw std::runtime_error("malformed signature");	 // wat (second character of hex string is null???)
		auto byt = strtoul(patIt, nullptr, 16);
		patternBytes.push_back((unsigned char) (byt & 0xFF));
		patternMask.push_back(0xFF);

		patIt += 2;
	}
	// Remove trailing ??
	while (!patternMask.empty() && patternMask.back() == 0) {
		patternMask.pop_back();
		patternBytes.pop_back();
	}

	if (patternMask.empty()) throw std::runtime_error("empty signature after sanitization");

	SearchMapValue val = {start, end - patternBytes.size()};
	if(enableCache)
		this->getOrAddToSearchMap(patternBytes, patternMask, val, allowAddToCache);
	else
		val.end += patternBytes.size();

	return this->findSignatureFast32<forward>(patternBytes, patternMask, val.start, val.end);
}

template void* MemScanner::findSignatureInRange<true>(const char*, uintptr_t, uintptr_t, bool, bool);
template void* MemScanner::findSignatureInRange<false>(const char*, uintptr_t, uintptr_t, bool, bool);

void MemScanner::SigRunner(MemScanner* me) {
	std::unique_lock g(me->shutdownMutex);

	while (!me->shouldShutdown) {
		if (me->doSearchSingleMapKey()) {
			std::this_thread::yield();
			continue;
		}

		me->wakeup.wait_for(g, std::chrono::milliseconds(5));
	}
}
void MemScanner::startSigRunnerThread() { sigRunnerThread = std::thread(MemScanner::SigRunner, this); }

void MemScanner::stopSigRunnerThread() {
	std::unique_lock g(shutdownMutex);
	shouldShutdown = true;
	g.unlock();
	wakeup.notify_all();
	if (sigRunnerThread.joinable()) sigRunnerThread.join();
}

void MemScanner::evictCache(){
	std::unique_lock g(this->shutdownMutex);
	std::lock_guard l1(searchMapMutex);
	std::lock_guard l2(this->needSearchMutex);
	this->searchMap.clear();
	this->needSearchMap.clear();
}