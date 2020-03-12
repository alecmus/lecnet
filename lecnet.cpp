/*
** lecnet.cpp - lecnet network library implementation
**
** lecnet network library
** Copyright (c) 2018 Alec T. Musasa (alecmus at live dot com)
**
*******************************************************************************
** This file is part of the liblec library which is released under the Creative
** Commons Attribution Non-Commercial 2.0 license (CC-BY-NC 2.0). See the file
** LICENSE.txt or go to https://github.com/alecmus/liblec/blob/master/LICENSE.md
** for full license details.
*/

#include "lecnet.h"
#include "versioninfo.h"

#include <Windows.h>
#include <strsafe.h>	// for StringCchPrintfA

// DllMain function
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved) {
	switch (ul_reason_for_call) {
	case DLL_PROCESS_ATTACH:
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		break;

	default:
		break;
	}
	return TRUE;
}

std::string liblec::lecnet::version() {
	return lecnetname + std::string(" ") + lecnetversion + std::string(" ") + lecnetdate;
}

namespace nmReadableSize {
	/*
	** adapted from wxWidgets whose license is as follows:
	**
	** Name:        src / common / filename.cpp
	** Purpose:     wxFileName - encapsulates a file path
	** Author:      Robert Roebling, Vadim Zeitlin
	** Modified by:
	** Created:     28.12.2000
	** RCS-ID:      $Id$
	** Copyright:   (c) 2000 Robert Roebling
	** Licence:     wxWindows licence
	*/

	// size conventions
	enum SizeConvention {
		SIZE_CONV_TRADITIONAL,  // 1024 bytes = 1 KB
		SIZE_CONV_SI            // 1000 bytes = 1 KB
	};

	std::string GetHumanReadableSize(const long double& dSize,
		const std::string& nullsize,
		int precision,
		SizeConvention conv) {
		// deal with trivial case first
		if (dSize == 0)
			return nullsize;

		// depending on the convention used the multiplier may be either 1000 or
		// 1024 and the binary infix may be empty (for "KB") or "i" (for "KiB")
		long double multiplier = 1024.;

		switch (conv) {
		case SIZE_CONV_TRADITIONAL:
			// nothing to do, this corresponds to the default values of both
			// the multiplier and infix string
			break;

		case SIZE_CONV_SI:
			multiplier = 1000;
			break;
		}

		const long double kiloByteSize = multiplier;
		const long double megaByteSize = multiplier * kiloByteSize;
		const long double gigaByteSize = multiplier * megaByteSize;
		const long double teraByteSize = multiplier * gigaByteSize;

		const long double bytesize = dSize;

		size_t const cchDest = 256;
		char pszDest[cchDest];

		if (bytesize < kiloByteSize)
			StringCchPrintfA(pszDest, cchDest, "%.*f B", 0, dSize);
		else if (bytesize < megaByteSize)
			StringCchPrintfA(pszDest, cchDest, "%.*f KB", precision, bytesize / kiloByteSize);
		else if (bytesize < gigaByteSize)
			StringCchPrintfA(pszDest, cchDest, "%.*f MB", precision, bytesize / megaByteSize);
		else if (bytesize < teraByteSize)
			StringCchPrintfA(pszDest, cchDest, "%.*f GB", precision, bytesize / gigaByteSize);
		else
			StringCchPrintfA(pszDest, cchDest, "%.*f TB", precision, bytesize / teraByteSize);

		return pszDest;
	}
}

std::string liblec::lecnet::format_size(unsigned long long size) {
	return nmReadableSize::GetHumanReadableSize(static_cast<long double>(size), "0 B", 1,
		nmReadableSize::SIZE_CONV_TRADITIONAL);
}
