#include <MemScanner/Macros.h>
#include <MemScanner/MemScanner.h>

#include <cassert>

namespace MemScanner {
	template <bool forward>
	void *MemScanner::findSignatureFastAVX2(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t rangeStart, uintptr_t rangeEnd) {
		if constexpr (!forward) return this->findSignatureFast1<forward>(bytes, mask, rangeStart, rangeEnd);
		const auto patternSize = (unsigned int) mask.size();
		if (patternSize <= 2) return this->findSignatureFast1<forward>(bytes, mask, rangeStart, rangeEnd);
		if (!MemScanner::hasFullAVXSupport()) return this->findSignatureFast8<true>(bytes, mask, rangeStart, rangeEnd);
		if (rangeStart + 32 + bytes.size() >= rangeEnd) MEM_UNLIKELY
		return this->findSignatureFast1<forward>(bytes, mask, rangeStart, rangeEnd);

		// Second byte is masked, fall back to slower method
		if (mask[1] != 0xFF) MEM_UNLIKELY
		return this->findSignatureFastAVX2_SecondByteMasked<forward>(bytes, mask, rangeStart, rangeEnd);

		const __m256i firstByteLaidOut = _mm256_set1_epi8(*reinterpret_cast<const char *>(&bytes[0]));	 // AVX
		const __m256i secondByteLaidOut = _mm256_set1_epi8(*reinterpret_cast<const char *>(&bytes[1]));	 // AVX
		// const __m256i thirdByteLaidOut = _mm256_set1_epi8(*reinterpret_cast<const char *>(&bytes[2])); // AVX

		const auto *maskStart = mask.data();
		const auto *bytesStart = bytes.data();
		const auto end = std::max(rangeStart, rangeEnd - 32u - patternSize);
		assert(end >= rangeStart);

		for (uintptr_t pCur = rangeStart; pCur <= end; pCur += 32) {
			const __m256i toBeCompared = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(pCur));  // AVX
			const __m256i cmp = _mm256_cmpeq_epi8(toBeCompared, firstByteLaidOut);					   // AVX2
			auto matches = (unsigned int) (_mm256_movemask_epi8(cmp));								   // AVX2

			const __m256i cmp2 = _mm256_cmpeq_epi8(toBeCompared, secondByteLaidOut);  // AVX2
			auto matches2 = (unsigned int) _mm256_movemask_epi8(cmp2);				  // AVX2

			matches &= (matches2 >> 1) | (0b1u << 31);
			if (!matches) continue;

			/*const __m256i cmp3 = _mm256_cmpeq_epi8(toBeCompared, thirdByteLaidOut); // AVX2
			unsigned int matches3 = _mm256_movemask_epi8(cmp3); // AVX2

			matches &= (matches3 >> 2) | (0b11 << 30);

			if (!matches) continue;*/

			unsigned long curBit = 0;
			while (bitscanforward(&curBit, matches)) {
				uintptr_t curP = pCur + curBit + 1;
				unsigned int off = 1;

				for (; off < patternSize; off++) {
					if (*(uint8_t *) curP != bytesStart[off] && maskStart[off] != 0) MEM_LIKELY
					break;
					curP++;
				}
				if (off >= patternSize) MEM_UNLIKELY return reinterpret_cast<void *>(pCur + curBit);

				matches = _blsr_u32(matches);
			}
		}

		// Scan the remaining bytes with the old algorithm
		return this->findSignatureFast1<true>(bytes, mask, end, rangeEnd);
	}

	template <bool forward>
	void *MemScanner::findSignatureFastAVX2_SecondByteMasked(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t rangeStart,
															 uintptr_t rangeEnd) {
		const auto patternSize = (unsigned int) bytes.size();
		// we don't need any checks, they were already done in the real avx2 impl

		const __m256i firstByteLaidOut = _mm256_set1_epi8(*reinterpret_cast<const char *>(&bytes[0]));	// AVX

		const auto *maskStart = mask.data();
		const auto *bytesStart = bytes.data();
		const auto end = std::max(rangeStart, rangeEnd - 32u - patternSize);

		for (uintptr_t pCur = rangeStart; pCur <= end; pCur += 32) {
			const __m256i toBeCompared = _mm256_loadu_si256(reinterpret_cast<const __m256i *>(pCur));  // AVX
			const __m256i cmp = _mm256_cmpeq_epi8(toBeCompared, firstByteLaidOut);					   // AVX2
			auto matches = (unsigned int) _mm256_movemask_epi8(cmp);								   // AVX2
			if (!matches) continue;

			unsigned long curBit = 0;
			while (bitscanforward(&curBit, matches)) {
				uintptr_t curP = pCur + curBit + 1;
				unsigned int off = 1;

				for (; off < patternSize; off++) {
					if (*(uint8_t *) curP != bytesStart[off] && maskStart[off] != 0) MEM_LIKELY
					break;
					curP++;
				}
				if (off >= patternSize) MEM_UNLIKELY return reinterpret_cast<void *>(pCur + curBit);

				matches = _blsr_u32(matches);
			}
		}

		return this->findSignatureFast1<true>(bytes, mask, end, rangeEnd);
	}

	template void *MemScanner::findSignatureFastAVX2<true>(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t rangeStart,
														   uintptr_t rangeEnd);

	template void *MemScanner::findSignatureFastAVX2<false>(const std::vector<uint8_t> &bytes, const std::vector<uint8_t> &mask, uintptr_t rangeStart,
															uintptr_t rangeEnd);
}  // namespace MemScanner