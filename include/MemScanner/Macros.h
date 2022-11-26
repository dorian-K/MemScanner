#pragma once

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <windows.h>
#include <psapi.h>
// clang-format on
#endif

#include <immintrin.h>

#ifdef _WIN32
#include <intrin.h>
inline unsigned char bitscanforward(unsigned long *index, unsigned long mask) { return _BitScanForward(index, mask); }

template <typename T>
inline void cpuid_impl(T cpuInfo[4], int f, int sub) {
	__cpuidex((int *) cpuInfo, f, sub);
}

#elif __GNUC__

#include <cpuid.h>

inline unsigned char bitscanforward(unsigned long *index, unsigned long mask) {
	auto bt = __builtin_ffsll(mask);
	if (bt != 0) {
		*index = bt - 1;
		return true;
	}
	return false;
}

inline void cpuid_impl(unsigned int cpuInfo[4], unsigned int function_id, int subfunction_id [[__maybe_unused__]]) {
	__get_cpuid(function_id, &cpuInfo[0], &cpuInfo[1], &cpuInfo[2], &cpuInfo[3]);
}

#else

template <typename T>
inline void cpuid_impl(T cpuInfo[4], int f, int sub) {
	__cpuidex((int *) cpuInfo, f, sub);
}
#endif

#ifndef _XCR_XFEATURE_ENABLED_MASK
#define _XCR_XFEATURE_ENABLED_MASK 0
#endif

#ifdef __cplusplus
#if defined(_MSVC_LANG) && _MSVC_LANG > __cplusplus
#define _STL_LANG _MSVC_LANG
#else  // ^^^ language mode is _MSVC_LANG / language mode is __cplusplus vvv
#define _STL_LANG __cplusplus
#endif	// ^^^ language mode is larger of _MSVC_LANG and __cplusplus ^^^
#else	// ^^^ determine compiler's C++ mode / no C++ support vvv
#define _STL_LANG 0L
#endif	// ^^^ no C++ support ^^^

#ifndef _HAS_CXX20
#if _HAS_CXX17 && _STL_LANG > 201703L
#define _HAS_CXX20 1
#else
#define _HAS_CXX20 0
#endif
#endif	// _HAS_CXX20

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