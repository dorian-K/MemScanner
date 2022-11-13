#pragma once

#include <vector>
#include <shared_mutex>
#include <mutex>
#include <deque>
#include <map>
#include <unordered_map>
#include <condition_variable>
#include <thread>

namespace MemScanner {

	class MemScanner {
	public:
		struct SearchMapKey {
			union {
				uint8_t bytes[8];
				uint64_t bytesHash = 0;
			};
			union {
				uint8_t mask[8];
                uint64_t maskHash = 0;
			};
			uint8_t numBytesUsed{};

			SearchMapKey() = default;

			SearchMapKey(const uint8_t *byt, const uint8_t *mas, int num) {
				numBytesUsed = std::min(num, 8);
				for (int i = 0; i < numBytesUsed; i++) {
					bytes[i] = byt[i];
					mask[i] = mas[i];
				}
				bytesHash &= maskHash;
			}

			SearchMapKey(const std::vector<uint8_t> &byt, const std::vector<uint8_t> &mas) {
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
		addToSearchMap(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t start,
					   uintptr_t end);

		bool
		findInSearchMap(const SearchMapKey &key, SearchMapValue &region, bool allowAdd, SearchMapValue &originalRegion);

		void getOrAddToSearchMap8Byte(const uint8_t *bytes, const uint8_t *mask, int size,
									  SearchMapValue &region, bool allowAdd, SearchMapValue &originalRegion);

		void getOrAddToSearchMap(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask,
								 SearchMapValue &region, bool allowAdd);

		static void SigRunner(MemScanner *me);

	public:
		~MemScanner();

		static bool hasFullAVXSupport();

		bool doSearchSingleMapKey();

		template<bool forward>
		void *findSignatureFast1(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask,
								 uintptr_t start, uintptr_t end);

		template<bool forward>
		void *findSignatureFast8(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask,
								 uintptr_t start, uintptr_t end);

		template<bool forward>
		void *findSignatureFastAVX2(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask,
								  uintptr_t start, uintptr_t end);

	protected:
		template<bool forward>
		void *findSignatureFastAVX2_SecondByteMasked(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask,
								  uintptr_t start, uintptr_t end);
	public:
		// start inclusive, end exclusive
		template<bool forward>
		void *findSignatureInRange(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& mask,
								   uintptr_t start, uintptr_t end,
								   bool enableCache = true,bool allowAddToCache = true);

		template<bool forward>
		void *findSignatureInRange(const char *szSignature,
								   uintptr_t start, uintptr_t end,
								   bool enableCache = true, bool allowAddToCache = true);

		void startSigRunnerThread();

		void stopSigRunnerThread();

		void evictCache();
	};

};