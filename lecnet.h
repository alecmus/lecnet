//
// lecnet.h - lecnet interface
//
// lecnet network library, part of the liblec library
// Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
//
// Released under the MIT license. For full details see the
// file LICENSE.txt
//

#pragma once

#if defined(LECNET_EXPORTS)
	#define lecnet_api __declspec(dllexport)
	#include "lecnet.h"
#else
	#define lecnet_api __declspec(dllimport)
	#include <liblec/lecnet.h>

	#if defined(_WIN64)
		#if defined(_DEBUG)
			#pragma comment(lib, "lecnet64d.lib")
		#else
			#pragma comment(lib, "lecnet64.lib")
		#endif
	#else
		#if defined(_DEBUG)
			#pragma comment(lib, "lecnet32d.lib")
		#else
			#pragma comment(lib, "lecnet32.lib")
		#endif
	#endif
#endif

#include <string>

namespace liblec {
	namespace lecnet {
		/// <summary>
		/// Get the version of the lecnet library.
		/// </summary>
		///
		/// <returns>
		/// Returns the version number as a string in the form "lecnet 1.0.0, 07 Nov 2018"
		/// </returns>
		std::string lecnet_api version();

		/// <summary>
		/// Network traffic, in bytes.
		/// </summary>
		struct network_traffic {
			unsigned long long in = 0;
			unsigned long long out = 0;
		};
	}
}
