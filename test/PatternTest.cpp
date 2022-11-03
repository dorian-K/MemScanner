#include <iostream>
#include <random>
#include <MemScanner/MemScanner.h>
#ifdef NDEBUG
#undef NDEBUG
#include <cassert>
#define NDEBUG
#else
#include <cassert>
#endif

#include <algorithm>


void testPatternAtEndOfBuffer(MemScanner::MemScanner& scanner, unsigned char* alloc, size_t allocSize){

	{ // without cache
		volatile auto res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false);
		assert(res == nullptr);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false);
		assert(res == nullptr);
		alloc[allocSize - 4] = 0x01;
		alloc[allocSize - 3] = 0x02;
		alloc[allocSize - 2] = 0x03;
		alloc[allocSize - 1] = 0x04;
		res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false);
		assert(res == &alloc[allocSize - 4]);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false);
		assert(res == &alloc[allocSize - 4]);
	}
	alloc[allocSize - 4] = 0x00;
	alloc[allocSize - 3] = 0x00;
	alloc[allocSize - 2] = 0x00;
	alloc[allocSize - 1] = 0x00;
	scanner.evictCache(); // For good measure
	{ // with cache
		volatile auto res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], true);
		assert(res == nullptr);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], true);
		assert(res == nullptr);
		alloc[allocSize - 4] = 0x01;
		alloc[allocSize - 3] = 0x02;
		alloc[allocSize - 2] = 0x03;
		alloc[allocSize - 1] = 0x04;
		scanner.evictCache();
		res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], true);
		assert(res == &alloc[allocSize - 4]);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], true);
		assert(res == &alloc[allocSize - 4]);
	}

	alloc[allocSize - 4] = 0x00;
	alloc[allocSize - 3] = 0x00;
	alloc[allocSize - 2] = 0x00;
	alloc[allocSize - 1] = 0x00;
	scanner.evictCache();
}

void testPatternAtStartOfBuffer(MemScanner::MemScanner& scanner, unsigned char* alloc, size_t allocSize){
	{ // without cache
		volatile auto res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false);
		assert(res == nullptr);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false);
		assert(res == nullptr);
		alloc[0] = 0x01;
		alloc[1] = 0x02;
		alloc[2] = 0x03;
		alloc[3] = 0x04;
		res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false);
		assert(res == &alloc[0]);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false);
		assert(res == &alloc[0]);
	}
	alloc[0] = 0x00;
	alloc[1] = 0x00;
	alloc[2] = 0x00;
	alloc[3] = 0x00;
	scanner.evictCache(); // For good measure
	{ // with cache
		volatile auto res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], true);
		assert(res == nullptr);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], true);
		assert(res == nullptr);
		alloc[0] = 0x01;
		alloc[1] = 0x02;
		alloc[2] = 0x03;
		alloc[3] = 0x04;
		res = scanner.findSignatureInRange<true>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], true);
		assert(res == &alloc[0]);
		res = scanner.findSignatureInRange<false>("01 02 03 04", (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], true);
		assert(res == &alloc[0]);
	}

	alloc[0] = 0x00;
	alloc[1] = 0x00;
	alloc[2] = 0x00;
	alloc[3] = 0x00;
	scanner.evictCache();
}
void benchmarkScan(MemScanner::MemScanner& scanner, unsigned char* alloc, size_t allocSize){
	const char* impossibleSig = "01 02 03 04 05 06 07 08 09 10 11 12";
	scanner.evictCache();
	assert(scanner.findSignatureInRange<true>(impossibleSig, (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false) == nullptr);
	assert(scanner.findSignatureInRange<false>(impossibleSig, (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false) == nullptr);

	auto start = std::chrono::high_resolution_clock::now();
	uintptr_t useful = 0;
	int i = 0;
	for(; i < 300; i++)
		useful += (uintptr_t)scanner.findSignatureInRange<true>(impossibleSig, (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false);

	assert(useful == 0);
	auto end = std::chrono::high_resolution_clock::now();
	double timePerScan = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / (double)i / 1000;
	printf("On average %.2fms / scan, %.1fMB/s\n", timePerScan, 1000. / timePerScan * (allocSize / 1000000.));
}

void benchmarkMultiThreadedScan(MemScanner::MemScanner& scanner, unsigned char* alloc, size_t allocSize, int numThreads = 4){
	const char* impossibleSig = "01 02 03 04 05 06 07 08 09 10 11 12";
	int numBytes = 12;
	scanner.evictCache();
	assert(scanner.findSignatureInRange<true>(impossibleSig, (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false) == nullptr);
	assert(scanner.findSignatureInRange<false>(impossibleSig, (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false) == nullptr);

	auto start = std::chrono::high_resolution_clock::now();
	int i = 0;
	for(; i < 300; i++){
		std::vector<std::thread> trs;

		auto doStuff = [&](uintptr_t from, uintptr_t to){
			volatile auto result = scanner.findSignatureInRange<true>(impossibleSig, from, to, false);
		};
		auto bytesPerSplit = allocSize / numThreads;
		assert(bytesPerSplit - numBytes >= 0);
		for(int t = 0; t < numThreads; t++){
			auto begin = t == 0 ? alloc : &alloc[bytesPerSplit * t - numBytes];
			auto end = t == numThreads - 1 ? &alloc[allocSize] : &alloc[bytesPerSplit * (t + 1)];

			trs.emplace_back(doStuff, (uintptr_t) begin, (uintptr_t) end);
		}

		for(std::thread& t : trs)
			if(t.joinable())
				t.join();
	}

	auto end = std::chrono::high_resolution_clock::now();
	double timePerScan = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / (double)i / 1000;
	printf("On average %.2fms / scan, %.1fMB/s\n", timePerScan, 1000. / timePerScan * (allocSize / 1000000.));
}

int main(){
    printf("AVX: %s\n", MemScanner::MemScanner::hasFullAVXSupport() ? "enabled" : "unsupported");

    const size_t allocSize = 0x5000000;// ~83MB

	auto* alloc = new unsigned char[allocSize];

	std::default_random_engine generator(123); // predictable seed
	std::uniform_int_distribution<uint64_t> distribution(0,0xFFFFFFFFFFFFFFFF);

	for(int i = 0; i < allocSize; i+=8)
		*reinterpret_cast<uint64_t*>(&alloc[i]) = distribution(generator);
	printf("Allocated!\n");

	MemScanner::MemScanner scanner; // Don't start sig runner thread, we do not need it
	testPatternAtEndOfBuffer(scanner, alloc, allocSize);
	testPatternAtStartOfBuffer(scanner, alloc, allocSize);
	printf("Tests success!\n");

	printf("Benchmarking single threaded performance...\n");
	for(int i = 0; i < 10; i++)
		benchmarkScan(scanner, alloc, allocSize);

	printf("Benchmarking multi threaded performance...\n");
    auto maxThreads = std::clamp(std::thread::hardware_concurrency(), 1u, 16u);
    int curNThreads = 2;
    while(curNThreads <= maxThreads){
        printf("%d threads:\n", curNThreads);
        for(int i = 0; i < 5; i++)
            benchmarkMultiThreadedScan(scanner, alloc, allocSize);
        curNThreads += 2;
    }


	return 0;
}