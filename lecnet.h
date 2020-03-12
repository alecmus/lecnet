/*
** lecnet.h - lecnet interface
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

#pragma once

#ifdef LECNET_EXPORTS
#define lecnet_api __declspec(dllexport)
#else
#define lecnet_api __declspec(dllimport)

#ifdef _WIN64

#ifdef _DEBUG
#pragma comment(lib, "lecnet64d.lib")
#else
#pragma comment(lib, "lecnet64.lib")
#endif // _DEBUG

#else

#ifdef _DEBUG
#pragma comment(lib, "lecnet32d.lib")
#else
#pragma comment(lib, "lecnet32.lib")
#endif // _DEBUG

#endif // _WIN64

#endif

#include <string>

namespace liblec {
	namespace lecnet {
		/// <summary>
		/// Get the version of the lecnet library.
		/// </summary>
		/// 
		/// <returns>
		/// Returns the version number as a string in the form "lecnet 1.0.0 07 Nov 2018"
		/// </returns>
		std::string lecnet_api version();

		/// <summary>
		/// Network traffic, in bytes.
		/// </summary>
		struct network_traffic {
			unsigned long long in = 0;
			unsigned long long out = 0;
		};

		/// <summary>
		/// Format data size in B, KB, MB, GB or TB.
		/// </summary>
		/// 
		/// <returns>
		/// Returns a formatted string in the form 5B, 45KB, 146MB, 52GB, 9TB etc.
		/// </returns>
		std::string lecnet_api format_size(unsigned long long size);

	}
}
