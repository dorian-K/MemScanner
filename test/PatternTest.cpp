#include <MemScanner/MemScanner.h>

#include <algorithm>
#include <cstring>
#include <iostream>
#include <random>

#ifdef NDEBUG
#undef NDEBUG
#include <cassert>
#define NDEBUG
#else
#include <cassert>
#endif

#ifdef _WIN32
#include <MemScanner/Mem.h>
#include <windows.h>
#endif

#include <filesystem>
#include <fstream>

namespace fs = std::filesystem;

unsigned char* knownGoodPatternSearch(const std::vector<uint8_t>& bytes, const std::vector<uint8_t>& mask, uintptr_t rangeStart, uintptr_t rangeEnd) {
	if (rangeStart + bytes.size() > rangeEnd) {
		assert(false);
		return nullptr;
	}
	assert(mask.at(0) != 0);
	auto* maskStart = mask.data();
	auto* bytesStart = bytes.data();
	auto startByte = reinterpret_cast<const uint8_t*>(bytesStart)[0];
	const auto end = rangeEnd - bytes.size();
	const auto patternSize = bytes.size();

	auto i = rangeStart;
	while (i <= end) {
		i = (uintptr_t) std::find(reinterpret_cast<uint8_t*>(i), reinterpret_cast<uint8_t*>(end + 1), startByte);
		if (i == end + 1) break;

		unsigned int off = 1;
		for (; off < patternSize; off++) {
			if (*(uint8_t*) (i + off) != bytesStart[off] && maskStart[off] != 0) break;
		}
		if (off == patternSize) return (unsigned char*) i;

		i++;
	}
	return nullptr;
}

void testPatternAtEndOfBuffer(MemScanner::MemScanner& scanner, unsigned char* alloc, size_t allocSize) {
	{  // without cache
		volatile auto res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false);
		assert(res == nullptr);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false);
		assert(res == nullptr);
		alloc[allocSize - 4] = 0x01;
		alloc[allocSize - 3] = 0x02;
		alloc[allocSize - 2] = 0x03;
		alloc[allocSize - 1] = 0x04;
		res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false);
		assert(res == &alloc[allocSize - 4]);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false);
		assert(res == &alloc[allocSize - 4]);
	}
	alloc[allocSize - 4] = 0x00;
	alloc[allocSize - 3] = 0x00;
	alloc[allocSize - 2] = 0x00;
	alloc[allocSize - 1] = 0x00;
	scanner.evictCache();  // For good measure
	{					   // with cache
		volatile auto res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], true);
		assert(res == nullptr);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], true);
		assert(res == nullptr);
		alloc[allocSize - 4] = 0x01;
		alloc[allocSize - 3] = 0x02;
		alloc[allocSize - 2] = 0x03;
		alloc[allocSize - 1] = 0x04;
		scanner.evictCache();
		res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], true);
		assert(res == &alloc[allocSize - 4]);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], true);
		assert(res == &alloc[allocSize - 4]);
	}

	alloc[allocSize - 4] = 0x00;
	alloc[allocSize - 3] = 0x00;
	alloc[allocSize - 2] = 0x00;
	alloc[allocSize - 1] = 0x00;
	scanner.evictCache();
}

void testPatternAtStartOfBuffer(MemScanner::MemScanner& scanner, unsigned char* alloc, size_t allocSize) {
	{  // without cache
		volatile auto res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false);
		assert(res == nullptr);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false);
		assert(res == nullptr);
		alloc[0] = 0x01;
		alloc[1] = 0x02;
		alloc[2] = 0x03;
		alloc[3] = 0x04;
		res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false);
		assert(res == &alloc[0]);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false);
		assert(res == &alloc[0]);
	}
	alloc[0] = 0x00;
	alloc[1] = 0x00;
	alloc[2] = 0x00;
	alloc[3] = 0x00;
	scanner.evictCache();  // For good measure
	{					   // with cache
		volatile auto res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], true);
		assert(res == nullptr);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], true);
		assert(res == nullptr);
		alloc[0] = 0x01;
		alloc[1] = 0x02;
		alloc[2] = 0x03;
		alloc[3] = 0x04;
		res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], true);
		assert(res == &alloc[0]);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], true);
		assert(res == &alloc[0]);
	}

	alloc[0] = 0x00;
	alloc[1] = 0x00;
	alloc[2] = 0x00;
	alloc[3] = 0x00;
	scanner.evictCache();
}
double benchmarkScan(MemScanner::MemScanner& scanner, unsigned char* alloc, size_t allocSize) {
	const char* impossibleSig = "01 02 03 04 05 06 07 08 09 10 11 12";
	scanner.evictCache();
	assert(scanner.findSignatureInRange<true>(impossibleSig, (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false, false) == nullptr);
	assert(scanner.findSignatureInRange<false>(impossibleSig, (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false, false) == nullptr);

	// Don't include pattern parsing in performance timer
	auto [patternBytes, patternMask] = MemScanner::MemScanner::ParseSignature(impossibleSig);
	auto start = std::chrono::high_resolution_clock::now();
	uintptr_t useful = 0;
	const size_t numIterations = std::clamp(/*assume 5000mb/s*/ 5000000000 / (allocSize + 1), (size_t) 20, (size_t) 50000000);
	unsigned int i = 0;
	for (; i < numIterations; i++)
		useful += (uintptr_t) scanner.findSignatureInRange<true>(patternBytes, patternMask, (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false, false);
	auto end = std::chrono::high_resolution_clock::now();
	assert(useful == 0);
	double microTimePerScan = (double) std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / (double) numIterations;
	double msTimePerScan = microTimePerScan / 1000;
	double mbPerS = (double) allocSize / microTimePerScan;
	printf("On average %.2fms / scan, %.1fMB/s\n", msTimePerScan, mbPerS);
	return mbPerS;
}

void benchmarkMultiThreadedScan(MemScanner::MemScanner& scanner, unsigned char* alloc, size_t allocSize, unsigned int numThreads) {
	const char* impossibleSig = "01 02 03 04 05 06 07 08 09 10 11 12";
	auto patternPair = MemScanner::MemScanner::ParseSignature(impossibleSig);
	auto patternBytes = std::get<0>(patternPair);
	auto patternMask = std::get<1>(patternPair);
	unsigned int numBytes = 12;
	scanner.evictCache();
	assert(scanner.findSignatureInRange<true>(patternBytes, patternMask, (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false) == nullptr);
	assert(scanner.findSignatureInRange<false>(patternBytes, patternMask, (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], false) == nullptr);

	std::vector<std::thread> trs;
	std::condition_variable cv;
	std::mutex mtx;
	unsigned int numWaitingThreads = 0;
	unsigned int curIter = 0;
	std::vector<unsigned int> numScanned{}, wakeupSignal{};
	for (unsigned int i = 0; i < numThreads; i++) {
		numScanned.push_back(0);
		wakeupSignal.push_back(0);
	}

	auto numIters = 0x500000000L / allocSize;

	auto doStuff = [&](uintptr_t from, uintptr_t to, unsigned int index) {
		while (true) {
			volatile auto result = scanner.findSignatureInRange<true>(patternBytes, patternMask, from, to, false, false);
			numScanned[index]++;
			if (result != nullptr) throw std::runtime_error("invalid: sig found in alloc");
			std::unique_lock l(mtx);
			numWaitingThreads++;
			if (numWaitingThreads == numThreads) {
				numWaitingThreads = 0;
				for (unsigned int i = 0; i < numThreads; i++) wakeupSignal[i] = 1;
				curIter++;
				cv.notify_all();
			} else
				cv.wait(l, [index, &wakeupSignal]() {
					return wakeupSignal[index] == 1;  // wakeup signal is needed because .wait can return spontaneously
				});
			wakeupSignal[index] = 0;

			if (curIter >= numIters) break;
		}
	};

	auto start = std::chrono::high_resolution_clock::now();

	auto bytesPerSplit = allocSize / numThreads;
	assert(bytesPerSplit >= numBytes);
	// printf("%llX - %llx / %llX\n", &alloc[0], &alloc[allocSize], bytesPerSplit);
	for (unsigned int t = 0; t < numThreads; t++) {
		auto begin = t == 0 ? alloc : &alloc[bytesPerSplit * t - numBytes];
		auto end = t == numThreads - 1 ? &alloc[allocSize] : &alloc[bytesPerSplit * (t + 1)];

		// printf("%d: %llX - %llx\n", t, begin, end);
		trs.emplace_back(doStuff, (uintptr_t) begin, (uintptr_t) end, t);
	}
	assert(trs.size() == (size_t) numThreads);

	for (std::thread& t : trs)
		if (t.joinable()) t.join();

	if (numScanned[0] != numIters) {
		printf("numScanned[0] != numIters: %d != %zd\n", numScanned[0], numIters);
		assert(false);
	}

	for (unsigned int i = 0; i < numThreads - 1; i++) {
		if (numScanned[i] != numScanned[i + 1]) {
			printf("numScanned[i] == numScanned[i+1]: %d != %d, i=%d\n", numScanned[i], numScanned[i + 1], i);
			assert(false);
		}
	}

	auto end = std::chrono::high_resolution_clock::now();
	double timePerScan = (double) std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / (double) numIters / 1000;
	printf("On average %.2fms / scan, %.1fMB/s\n", timePerScan, 1000. / timePerScan * ((double) allocSize / 1000000.));
}

void testBuffer(MemScanner::MemScanner& scanner, size_t allocSize, unsigned char* alloc) {
	if (allocSize >= 4) {
		testPatternAtEndOfBuffer(scanner, alloc, allocSize);
		testPatternAtStartOfBuffer(scanner, alloc, allocSize);
	}
	printf("Tests success! (Allocation size: %zd)\n", allocSize);
}

void benchmarkBuffer(MemScanner::MemScanner& scanner, size_t allocSize, unsigned char* alloc, const std::string& type) {
	printf("Benchmarking single threaded %s performance...\n", type.c_str());
	for (int i = 0; i < 10; i++) benchmarkScan(scanner, alloc, allocSize);

	printf("Benchmarking multi threaded %s performance...\n", type.c_str());
	auto maxThreads = std::clamp(std::thread::hardware_concurrency() / 2, 1u, 64u);
	unsigned int curNThreads = 2;
	while (curNThreads <= maxThreads) {
		printf("%d threads:\n", curNThreads);
		for (int i = 0; i < 5; i++) benchmarkMultiThreadedScan(scanner, alloc, allocSize, curNThreads);
		if (curNThreads < 6)
			curNThreads++;
		else if (curNThreads <= 16)
			curNThreads += 2;
		else
			curNThreads += 4;
	}
}

void testSyntheticBuffer(bool doBenchmark = true) {
	const size_t allocSize = 0x5000000;	 // ~83MB

	auto* alloc = new unsigned char[allocSize];

	std::default_random_engine generator(123);	// predictable seed
	std::uniform_int_distribution<uint64_t> distribution(0, 0xFFFFFFFFFFFFFFFF);

	for (size_t i = 0; i < allocSize; i += 8) *reinterpret_cast<uint64_t*>(&alloc[i]) = distribution(generator);
	printf("Allocated!\n");

	MemScanner::MemScanner scanner;	 // Don't start sig runner thread, we do not need it
	testBuffer(scanner, allocSize, alloc);
	if (doBenchmark) benchmarkBuffer(scanner, allocSize, alloc, "synthetic");

	delete[] alloc;
}

void testSyntheticBufferSize(bool enableBenchmark) {
	const size_t maxBuffer = enableBenchmark ? 0x10000000 : 0x100000;

	for (size_t allocSize = 0x8; allocSize <= maxBuffer; allocSize *= 2) {
		auto* alloc = new unsigned char[allocSize];
		assert(alloc != nullptr);

		std::default_random_engine generator(123);	// predictable seed
		std::uniform_int_distribution<uint64_t> distribution(0, 0xFFFFFFFFFFFFFFFF);

		for (size_t i = 0; i < allocSize; i += 8) *reinterpret_cast<uint64_t*>(&alloc[i]) = distribution(generator);
		printf("Allocated!\n");

		MemScanner::MemScanner scanner;	 // Don't start sig runner thread, we do not need it
		testBuffer(scanner, allocSize, alloc);
		if (enableBenchmark) {
			printf("Benchmarking single threaded synthetic 0x%zX buffer...\n", allocSize);
			for (int i = 0; i < 5; i++) benchmarkScan(scanner, alloc, allocSize);
		}

		delete[] alloc;
	}
}

template <bool testCache>
void testRandomSyntheticBufferSize() {
	const size_t maxBuffer = 0x4000;
	const int numSizeIterations = 1000;

	std::default_random_engine generator(testCache ? 123 : 124);  // predictable seed
	std::uniform_int_distribution<uint64_t> distribution(0, 0xFFFFFFFFFFFFFFFF);
	std::uniform_int_distribution<uint64_t> sizeDistribution(64, maxBuffer);
	std::uniform_int_distribution<uint64_t> largePatternSizeDistribution(8, 128);
	std::uniform_int_distribution<uint64_t> smallPatternSizeDistribution(1, 8);
	std::uniform_int_distribution<uint64_t> binDist(0, 1);
	for (unsigned int e = 1; e < numSizeIterations; e++) {
		if (e % 10 == 0) printf("iteration %d/%d (%.1f%%)\n", e, numSizeIterations, (double) e / numSizeIterations * 100);
		size_t allocSize;
		if (e <= 384)
			allocSize = (size_t) e;
		else {
			allocSize = sizeDistribution(generator);
		}
		auto* alloc = new unsigned char[allocSize + 1];
		if (alloc == nullptr) throw std::runtime_error("out of memory");
		alloc[allocSize] = 0xFF;

		for (size_t i = 0; i < (allocSize & (~7u)); i += 8) *reinterpret_cast<uint64_t*>(&alloc[i]) = distribution(generator);
		for (size_t i = (allocSize & (~7u)); i < allocSize; i++) alloc[i] = (unsigned char) distribution(generator);

		MemScanner::MemScanner scanner;
		for (int r = 0; r < 5000; r++) {
			// generate a random pattern and test against a known good algorithm
			auto patternSize = (r % 3 == 0) ? largePatternSizeDistribution(generator) : smallPatternSizeDistribution(generator);
			while (patternSize > allocSize) patternSize = smallPatternSizeDistribution(generator);
			std::vector<uint8_t> pattern(patternSize);
			std::vector<uint8_t> mask(patternSize, 0xFF);

			for (size_t i = 0; i < (patternSize & (~7u)); i += 8) *reinterpret_cast<uint64_t*>(&pattern[i]) = distribution(generator);
			for (size_t i = (patternSize & (~7u)); i < patternSize; i++) pattern[i] = (unsigned char) distribution(generator);

			if (r > 1000) {
				for (size_t i = 1; i < patternSize; i++)
					if (binDist(generator) == 1) mask[i] = 0;
			}
			assert(pattern.size() == mask.size());

			uintptr_t goodFind;
			bool shouldFindPattern = false;
			while (true) {
				goodFind = (uintptr_t) knownGoodPatternSearch(pattern, mask, (uintptr_t) alloc, (uintptr_t) &alloc[allocSize]);
				assert(!(shouldFindPattern && goodFind == 0));
				auto ourFind =
					(uintptr_t) scanner.findSignatureInRange<true>(pattern, mask, (uintptr_t) alloc, (uintptr_t) &alloc[allocSize], testCache, testCache);

				if (goodFind != ourFind) {
					fprintf(stderr, "\nMismatch: %zX != %zX\n", goodFind, ourFind);
					if (goodFind != 0) fprintf(stderr, "goodFind = %zd\n", goodFind - (uintptr_t) alloc);
					if (ourFind != 0) fprintf(stderr, "ourFind = %zd\n", ourFind - (uintptr_t) alloc);
					fprintf(stderr, "\nAlloc Size: %zd\n", allocSize);
					fprintf(stderr, "Pattern(%zd): \t", pattern.size());
					for (auto i : pattern) fprintf(stderr, "%02X ", i);
					fprintf(stderr, "\n");
					fprintf(stderr, "Mask(%zd): \t", mask.size());
					for (auto i : mask) fprintf(stderr, "%02X ", i);

					fprintf(stderr, "\n");

					assert(false);
				}
				if (goodFind != 0 || testCache) break;

				// Place the pattern somewhere in the buffer
				std::uniform_int_distribution<uint64_t> placeForPattern(0, allocSize - patternSize);
				auto place = placeForPattern(generator);
				for (auto i = 0u; i < patternSize; i++) {
					if (mask.at(i) == 0) continue;
					alloc[i + place] = pattern[i];
				}
				shouldFindPattern = true;
			}
		}

		delete[] alloc;
	}
}

void testSelf() {
#ifdef _WIN32
	MemScanner::Mem mem{};
	auto exeHandle = (void*) GetModuleHandleA(nullptr);
	auto textSection = MemScanner::Mem::GetSectionRange(exeHandle, ".text");
	auto allocSize = textSection.second - textSection.first;
	auto* alloc = (unsigned char*) textSection.first;
	printf("Self test size: %lld (%llX)\n", allocSize, allocSize);

	benchmarkBuffer(mem.getScanner(), allocSize, alloc, ".exe");
#else
	printf("Self test is only implemented on windows!");
#endif
}

void testSecondary(const fs::path& path) {
	assert(fs::exists(path));
	assert(fs::is_regular_file(path));

	std::basic_fstream<unsigned char> inStream(path);
	if (!inStream.good()) throw std::runtime_error("could not open infile");
	auto file_size = fs::file_size(path);
	auto buffer = std::make_unique<unsigned char[]>(file_size);
	inStream.read(buffer.get(), (std::streamsize) file_size);
	inStream.close();

	MemScanner::MemScanner scanner{};
	benchmarkBuffer(scanner, file_size, buffer.get(), "secondary exe");
}

int main(int argc, char* argv[]) {
	printf("AVX: %s\n", MemScanner::MemScanner::hasFullAVXSupport() ? "enabled" : "unsupported");

	bool enableBenchmark = true;
	if (argc >= 2) {
		for (int i = 0; i < argc; i++) {
			if (strcmp(argv[i], "nobenchmark") == 0) enableBenchmark = false;
		}
	}

	testRandomSyntheticBufferSize<false>();
	// testRandomSyntheticBufferSize<true>(); // test with cache enabled

	testSyntheticBufferSize(enableBenchmark);
	testSyntheticBuffer(enableBenchmark);
	if (enableBenchmark) testSelf();
	// testSecondary(fs::path("/"));

	return 0;
}