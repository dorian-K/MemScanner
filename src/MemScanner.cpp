#include <MemScanner/Macros.h>
#include <MemScanner/MemScanner.h>

#include <array>
#include <cstring>
#include <iostream>

namespace MemScanner {

	void MemScanner::addToSearchMap(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t start, uintptr_t end) {
		if (bytes.size() > 8) return;
		SearchMapKey key(bytes, mask);
		SearchMapValue val{start, end};
		std::lock_guard lock(searchMapMutex);
		if (searchMap.size() > 2000) return;
		searchMap[key] = val;
	}

	bool MemScanner::findInSearchMap(const SearchMapKey &key, SearchMapValue &region, bool allowAdd, SearchMapValue &originalRegion) {
		std::shared_lock lock(searchMapMutex);

		auto res = searchMap.find(key);
		if (res == searchMap.end()) {
			if (allowAdd) {
				lock.unlock();
				std::lock_guard g(needSearchMutex);
				if (needSearchMap.size() < 200) {
					for (const auto &[prio, entr] : needSearchMap)
						if (entr.key == key) return false;	// already in needSearchMap
					needSearchMap.insert({0, {key, false, originalRegion}});
				}
			}
			return false;
		}

		auto &val = res->second;
		region.start = std::max(region.start, val.start);
		region.end = std::min(region.end, val.end);

		return true;
	}

	void MemScanner::getOrAddToSearchMap8Byte(const uint8_t *bytes, const uint8_t *mask, int size, SearchMapValue &region, bool allowAdd,
											  SearchMapValue &originalRegion) {
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

	void MemScanner::getOrAddToSearchMap(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, SearchMapValue &region, bool allowAdd) {
		SearchMapValue originalRegion(region);
		originalRegion.end += bytes.size();
		getOrAddToSearchMap8Byte(bytes.data(), mask.data(), (int) bytes.size(), region, allowAdd, originalRegion);
		if (bytes.size() <= 8 || region.start >= region.end) return;
		region.end -= bytes.size();
		// try all the permutations
		for (unsigned int i = 1; i < bytes.size(); i++) {
			if (mask[i] == 0) continue;
			SearchMapValue tempRegion(region);
			getOrAddToSearchMap8Byte(bytes.data() + i, mask.data() + i, (int) bytes.size() - i, tempRegion, allowAdd, originalRegion);
			region.start = std::max(region.start, tempRegion.start - i);
		}

		region.end += bytes.size();
	}

	MemScanner::~MemScanner() { this->stopSigRunnerThread(); }

	bool hasAvxOSSupport() {
		// http://stackoverflow.com/a/22521619/922184
		bool avxSupported = false;

		unsigned int cpuInfo[4]{};
		cpuid_impl(cpuInfo, 1, 0);

		bool osUsesXSAVE_XRSTORE = (cpuInfo[2] & (1 << 27)) != 0;
		bool cpuAVXSupport = (cpuInfo[2] & (1 << 28)) != 0;

		if (osUsesXSAVE_XRSTORE && cpuAVXSupport) {
			uint64_t xcrFeatureMask = _xgetbv(_XCR_XFEATURE_ENABLED_MASK);
			avxSupported = (xcrFeatureMask & 0x6) == 0x6;
		}

		return avxSupported;
	}

	bool MemScanner::hasFullAVXSupport() {
		static int cached = -1;
		if (cached != -1) return cached == 1;

		// OS Support
		if (!hasAvxOSSupport()) {
			cached = 0;
			return false;
		}
		// CPU support - https://github.com/Mysticial/FeatureDetector/blob/master/src/x86/cpu_x86.cpp#L109
		bool avx = false, avx2 = false;
		unsigned int info[4]{};
		cpuid_impl(info, 0, 0);
		int nIds = info[0];

		if (nIds >= 0x00000001) {
			cpuid_impl(info, 0x00000001, 0);

			avx = (info[2] & ((int) 1 << 28)) != 0;
		}
		if (nIds >= 0x00000007) {
			cpuid_impl(info, 0x00000007, 0);
			avx2 = (info[1] & ((int) 1 << 5)) != 0;
		}

		if (avx && avx2) {
			cached = 1;
			return true;
		} else {
			cached = 0;
			return false;
		}
	}

	std::pair<std::vector<uint8_t>, std::vector<uint8_t>> MemScanner::ParseSignature(const char *szSignature) {
		std::vector<uint8_t> patternBytes;
		patternBytes.reserve(strlen(szSignature) / 3 + 1);
		std::vector<uint8_t> patternMask;
		patternMask.reserve(strlen(szSignature) / 3 + 1);

		for (const char *patIt = szSignature; *patIt;) {
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
			patternBytes.push_back((uint8_t) (byt & 0xFF));
			patternMask.push_back(0xFF);

			patIt += 2;
		}
		// Remove trailing ??
		while (!patternMask.empty() && patternMask.back() == 0) {
			patternMask.pop_back();
			patternBytes.pop_back();
		}

		return {patternBytes, patternMask};
	}

	bool MemScanner::doSearchSingleMapKey() {
		SearchMapKey key;
		SearchMapValue regionToBeSearched;
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

		SearchMapValue val{regionToBeSearched.start, regionToBeSearched.end - key.numBytesUsed};
		std::vector<uint8_t> bytes(key.bytes, &key.bytes[key.numBytesUsed]);
		std::vector<uint8_t> mask(key.mask, &key.mask[key.numBytesUsed]);
		getOrAddToSearchMap(bytes, mask, val, false);
		if (val.start > val.end) goto end;

		{
			// uintptr_t prevSearchSpace = val.end - val.start;
			auto start = reinterpret_cast<uintptr_t>(MemScanner::findSignatureFastAVX2<true>(bytes, mask, val.start, val.end));
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
			// dprnt("Key not found back in map!");
			return true;
		}
		needSearchMap.erase(iter);
		return true;
	}

	template <bool forward>
	void *MemScanner::findSignatureFast1(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t rangeStart, uintptr_t rangeEnd) {
		const int patternSize = (int) mask.size();
		if (patternSize < 1) MEM_UNLIKELY
		throw std::runtime_error("invalid pattern");
		if (rangeStart + bytes.size() > rangeEnd) MEM_UNLIKELY
		return nullptr;
		auto *maskStart = mask.data();
		auto *bytesStart = bytes.data();
		auto startByte = reinterpret_cast<const uint8_t *>(bytesStart)[0];
		auto startMask = reinterpret_cast<const uint8_t *>(maskStart)[0];
		if (startMask == 0) MEM_UNLIKELY
		throw std::runtime_error("invalid pattern");
		const auto end = rangeEnd - patternSize;

		for (uintptr_t pCur = forward ? rangeStart : end; forward ? (pCur <= end) : (pCur >= rangeStart); pCur += (forward ? 1 : -1)) {
			if (*reinterpret_cast<uint8_t *>(pCur) == startByte) MEM_UNLIKELY {
					uintptr_t curP = pCur + 1;
					int off = 1;

					for (; off < patternSize; off++) {
						if (*(uint8_t *) curP != bytesStart[off] && maskStart[off] != 0) MEM_LIKELY
						break;
						curP++;
					}
					if (off == patternSize) MEM_UNLIKELY
					return reinterpret_cast<void *>(pCur);
				}
		}

		return nullptr;
	}

	template void *MemScanner::findSignatureFast1<true>(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t rangeStart,
														uintptr_t rangeEnd);

	template void *MemScanner::findSignatureFast1<false>(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t rangeStart,
														 uintptr_t rangeEnd);

	template <bool forward>
	void *MemScanner::findSignatureFast8(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t rangeStart, uintptr_t rangeEnd) {
		if constexpr (!forward) return this->findSignatureFast1<forward>(bytes, mask, rangeStart, rangeEnd);
		const int patternSize = (int) mask.size();
		if (patternSize < 8) return this->findSignatureFast1<forward>(bytes, mask, rangeStart, rangeEnd);
		if (rangeStart + bytes.size() > rangeEnd) MEM_UNLIKELY
		return nullptr;

		const auto *maskStart = mask.data();
		const auto startMask = reinterpret_cast<const uint64_t *>(maskStart)[0];

		if (startMask != 0xFFFFFFFFFFFFFFFFU)
			MEM_LIKELY	// 1 Byte scan is more efficient with a mask
				return this->findSignatureFast1<forward>(bytes, mask, rangeStart, rangeEnd);

		const auto *bytesStart = bytes.data();
		const auto startByte = reinterpret_cast<const uint64_t *>(bytesStart)[0];
		const auto end = rangeEnd - patternSize;

		for (uintptr_t pCur = rangeStart; pCur <= end; pCur++) {
			if (*reinterpret_cast<uint64_t *>(pCur) == startByte) MEM_UNLIKELY {
					uintptr_t curP = pCur + 8;
					int off = 8;
					for (; off < patternSize; off++) {
						if (*(uint8_t *) curP != bytesStart[off] && maskStart[off] != 0) MEM_LIKELY
						break;
						curP++;
					}
					if (off == patternSize) return reinterpret_cast<void *>(pCur);
				}
		}

		return nullptr;
	}

	template void *MemScanner::findSignatureFast8<true>(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t rangeStart,
														uintptr_t rangeEnd);

	template void *MemScanner::findSignatureFast8<false>(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t rangeStart,
														 uintptr_t rangeEnd);

	template <bool forward>
	void *MemScanner::findSignatureInRange(const std::vector<uint8_t> &patternBytes, const std::vector<uint8_t> &patternMask, uintptr_t start, uintptr_t end,
										   bool enableCache, bool allowAddToCache) {
		if (patternBytes.empty() || patternBytes.size() != patternMask.size()) throw std::runtime_error("invalid signature size");

		SearchMapValue val{start, end - patternBytes.size()};
		if (enableCache)
			this->getOrAddToSearchMap(patternBytes, patternMask, val, allowAddToCache);
		else
			val.end += patternBytes.size();

		return this->findSignatureFastAVX2<forward>(patternBytes, patternMask, val.start, val.end);
	}

	template void *MemScanner::findSignatureInRange<true>(const std::vector<uint8_t> &, const std::vector<uint8_t> &, uintptr_t, uintptr_t, bool, bool);

	template void *MemScanner::findSignatureInRange<false>(const std::vector<uint8_t> &, const std::vector<uint8_t> &, uintptr_t, uintptr_t, bool, bool);

	template <bool forward>
	void *MemScanner::findSignatureInRange(const char *szSignature, uintptr_t start, uintptr_t end, bool enableCache, bool allowAddToCache) {
		auto [patternBytes, patternMask] = MemScanner::ParseSignature(szSignature);

		if (patternMask.empty()) throw std::runtime_error("empty signature after sanitization");

		return this->findSignatureInRange<forward>(patternBytes, patternMask, start, end, enableCache, allowAddToCache);
	}

	template void *MemScanner::findSignatureInRange<true>(const char *, uintptr_t, uintptr_t, bool, bool);

	template void *MemScanner::findSignatureInRange<false>(const char *, uintptr_t, uintptr_t, bool, bool);

	void MemScanner::SigRunner(MemScanner *me) {
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

	void MemScanner::evictCache() {
		std::unique_lock g(this->shutdownMutex);
		std::lock_guard l1(searchMapMutex);
		std::lock_guard l2(this->needSearchMutex);
		this->searchMap.clear();
		this->needSearchMap.clear();
	}

}  // namespace MemScanner