#include <iostream>
#include <random>
#include <MemScanner/MemScanner.h>
#include <MemScanner/Mem.h>
#ifdef NDEBUG
#undef NDEBUG
#include <cassert>
#define NDEBUG
#else
#include <cassert>
#endif

#ifdef _WIN32
#include <windows.h>
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
	assert(scanner.findSignatureInRange<true>(impossibleSig, (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false, false) == nullptr);
	assert(scanner.findSignatureInRange<false>(impossibleSig, (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false, false) == nullptr);

	auto start = std::chrono::high_resolution_clock::now();
	uintptr_t useful = 0;
	int i = 0;
	for(; i < 300; i++)
		useful += (uintptr_t)scanner.findSignatureInRange<true>(impossibleSig, (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false, false);

	assert(useful == 0);
	auto end = std::chrono::high_resolution_clock::now();
	double timePerScan = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / (double)i / 1000;
	printf("On average %.2fms / scan, %.1fMB/s\n", timePerScan, 1000. / timePerScan * (allocSize / 1000000.));
}

void benchmarkMultiThreadedScan(MemScanner::MemScanner& scanner, unsigned char* alloc, size_t allocSize, int numThreads){
	const char* impossibleSig = "01 02 03 04 05 06 07 08 09 10 11 12";
	int numBytes = 12;
	scanner.evictCache();
	assert(scanner.findSignatureInRange<true>(impossibleSig, (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false) == nullptr);
	assert(scanner.findSignatureInRange<false>(impossibleSig, (uintptr_t)alloc, (uintptr_t)&alloc[allocSize], false) == nullptr);



	std::vector<std::thread> trs;
	std::condition_variable cv;
	std::mutex mtx;
	int numWaitingThreads = 0;
	int curIter = 0;
	std::vector<int> numScanned{}, wakeupSignal{};
	for(int i = 0; i < numThreads; i++){
		numScanned.push_back(0);
		wakeupSignal.push_back(0);
	}

	uint64_t numIters = 0x500000000 / allocSize;

	auto doStuff = [&](uintptr_t from, uintptr_t to, int index){
		while(true){
			volatile auto result = scanner.findSignatureInRange<true>(impossibleSig, from, to, false, false);
			numScanned[index]++;
			if(result != nullptr)
				throw std::runtime_error("invalid: sig found in alloc");
			std::unique_lock l(mtx);
			numWaitingThreads++;
			if(numWaitingThreads == numThreads){
				numWaitingThreads = 0;
				for(int i = 0; i <  numThreads; i++)
					wakeupSignal[i] = 1;
				curIter++;
				cv.notify_all();
			}else
				cv.wait(l, [index, &wakeupSignal](){
					return wakeupSignal[index] == 1; // wakeup signal is needed because .wait can return spontaneously
				});
			wakeupSignal[index] = 0;

			if(curIter >= numIters)
				break;
		}
	};

	auto start = std::chrono::high_resolution_clock::now();

	auto bytesPerSplit = allocSize / numThreads;
	assert(bytesPerSplit - numBytes >= 0);
	//printf("%llX - %llx / %llX\n", &alloc[0], &alloc[allocSize], bytesPerSplit);
	for(int t = 0; t < numThreads; t++){
		auto begin = t == 0 ? alloc : &alloc[bytesPerSplit * t - numBytes];
		auto end = t == numThreads - 1 ? &alloc[allocSize] : &alloc[bytesPerSplit * (t + 1)];

		//printf("%d: %llX - %llx\n", t, begin, end);
		trs.emplace_back(doStuff, (uintptr_t) begin, (uintptr_t) end, t);
	}
	assert(trs.size() == numThreads);

	for(std::thread& t : trs)
		if(t.joinable())
			t.join();

	if(numScanned[0] != numIters){
		printf("numScanned[0] != numIters: %d != %lld\n", numScanned[0], numIters);
		assert(false);
	}

	for(int i = 0; i < numThreads - 1; i++){
		if(numScanned[i] != numScanned[i+1]){
			printf("numScanned[i] == numScanned[i+1]: %d != %d, i=%d\n", numScanned[i], numScanned[i+1], i);
			assert(false);
		}
	}

	auto end = std::chrono::high_resolution_clock::now();
	double timePerScan = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / (double)numIters / 1000;
	printf("On average %.2fms / scan, %.1fMB/s\n", timePerScan, 1000. / timePerScan * (allocSize / 1000000.));
}

void testSyntheticBuffer(){
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

	printf("Benchmarking single threaded synthetic performance...\n");
	for(int i = 0; i < 10; i++)
		benchmarkScan(scanner, alloc, allocSize);

	printf("Benchmarking multi threaded synthetic performance...\n");
	auto maxThreads = std::clamp(std::thread::hardware_concurrency() / 2, 1u, 64u);
	int curNThreads = 2;
	while(curNThreads <= maxThreads){
		printf("%d threads:\n", curNThreads);
		for(int i = 0; i < 5; i++)
			benchmarkMultiThreadedScan(scanner, alloc, allocSize, curNThreads);
		if(curNThreads < 6)
			curNThreads++;
		else if(curNThreads <= 16)
			curNThreads += 2;
		else
			curNThreads += 4;
	}
}

void testSelf(){
	MemScanner::Mem mem{};
	auto exeHandle = (void *) GetModuleHandleA(nullptr);
	auto textSection = MemScanner::Mem::GetSectionRange(exeHandle, ".text");
	auto allocSize = textSection.second - textSection.first;
	auto* alloc = (unsigned char*) textSection.first;
	printf("Self test size: %lld (%llX)\n", allocSize, allocSize);

	printf("Benchmarking single threaded .exe performance...\n");
	for(int i = 0; i < 10; i++)
		benchmarkScan(mem.getScanner(), alloc, allocSize);

	printf("Benchmarking multi threaded .exe performance...\n");
	auto maxThreads = std::clamp(std::thread::hardware_concurrency() / 2, 1u, 64u);
	int curNThreads = 2;
	while(curNThreads <= maxThreads){
		printf("%d threads:\n", curNThreads);
		for(int i = 0; i < 5; i++)
			benchmarkMultiThreadedScan(mem.getScanner(), alloc, allocSize, curNThreads);
		if(curNThreads < 6)
			curNThreads++;
		else if(curNThreads <= 16)
			curNThreads += 2;
		else
			curNThreads += 4;
	}
}

void testSecondary(){

}

int main(){
    printf("AVX: %s\n", MemScanner::MemScanner::hasFullAVXSupport() ? "enabled" : "unsupported");

	testSyntheticBuffer();
	testSelf();

	return 0;
}