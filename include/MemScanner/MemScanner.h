#pragma once

#include <vector>
#include <shared_mutex>
#include <mutex>
#include <deque>
#include <map>
#include <unordered_map>
#include <condition_variable>

namespace MemScanner {

	class MemScanner {
	public:
		struct SearchMapKey {
			union {
				unsigned char bytes[8];
				uint64_t bytesHash = 0;
			};
			union {
				unsigned char mask[8];
                uint64_t maskHash = 0;
			};
			unsigned char numBytesUsed{};

			SearchMapKey() = default;

			SearchMapKey(const unsigned char *byt, const unsigned char *mas, int num) {
				numBytesUsed = std::min(num, 8);
				for (int i = 0; i < numBytesUsed; i++) {
					bytes[i] = byt[i];
					mask[i] = mas[i];
				}
				bytesHash &= maskHash;
			}

			SearchMapKey(const std::vector<unsigned char> &byt, const std::vector<unsigned char> &mas) {
				numBytesUsed = std::min((int) byt.size(), 8);
				for (int i = 0; i < numBytesUsed; i++) {
					bytes[i] = byt[i];
					mask[i] = mas[i];
				}
				bytesHash &= maskHash;
			}

			bool operator==(const SearchMapKey &p) const {
				return bytesHash == p.bytesHash && numBytesUsed == p.numBytesUsed && maskHash == p.maskHash;
			}

			bool operator!=(const SearchMapKey &p) const {
				return !(*this == p);
			}
		};

		struct hash_fn {
			std::size_t operator()(const SearchMapKey &o) const { return std::hash<uint64_t>()(o.bytesHash); }
		};

		struct SearchMapValue {
			uintptr_t start = 0, end = 0;

            SearchMapValue() = default;
            SearchMapValue(const SearchMapValue&) = default;
            SearchMapValue(SearchMapValue&&) = default;
            SearchMapValue(uintptr_t start, uintptr_t end) : start(start), end(end) {};

			SearchMapValue &operator=(const SearchMapValue &) = default;
            SearchMapValue &operator=(SearchMapValue &&) = default;
		};

		struct NeedSearchObj {
			SearchMapKey key;
			bool isInSearch = false;
			SearchMapValue regionToBeSearched;
		};
	private:

		bool shouldShutdown;
		std::mutex shutdownMutex;
		std::condition_variable wakeup;
		std::thread sigRunnerThread;

		std::shared_mutex searchMapMutex;
		std::unordered_map<SearchMapKey, SearchMapValue, hash_fn> searchMap;
		std::recursive_mutex needSearchMutex;

		std::multimap<int, NeedSearchObj> needSearchMap;

		void
		addToSearchMap(const std::vector<unsigned char> &bytes, const std::vector<unsigned char> &mask, uintptr_t start,
					   uintptr_t end);

		bool
		findInSearchMap(const SearchMapKey &key, SearchMapValue &region, bool allowAdd, SearchMapValue &originalRegion);

		void getOrAddToSearchMap8Byte(const unsigned char *bytes, const unsigned char *mask, int size,
									  SearchMapValue &region, bool allowAdd, SearchMapValue &originalRegion);

		void getOrAddToSearchMap(const std::vector<unsigned char> &bytes, const std::vector<unsigned char> &mask,
								 SearchMapValue &region, bool allowAdd);

		static void SigRunner(MemScanner *me);

	public:
		~MemScanner();

		static bool hasFullAVXSupport();

		bool doSearchSingleMapKey();

		template<bool forward>
		void *findSignatureFast1(const std::vector<unsigned char> &bytes, const std::vector<unsigned char> &mask,
								 uintptr_t start, uintptr_t end);

		template<bool forward>
		void *findSignatureFast8(const std::vector<unsigned char> &bytes, const std::vector<unsigned char> &mask,
								 uintptr_t start, uintptr_t end);

		template<bool forward>
		void *findSignatureFast32(const std::vector<unsigned char> &bytes, const std::vector<unsigned char> &mask,
								  uintptr_t start, uintptr_t end);

		template<bool forward>
		// start inclusive, end exclusive
		void *findSignatureInRange(const char *szSignature, uintptr_t start, uintptr_t end, bool enableCache = true,
								   bool allowAddToCache = true);

		void startSigRunnerThread();

		void stopSigRunnerThread();

		void evictCache();
	};

};