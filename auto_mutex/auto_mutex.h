/*
** auto_mutex.h - auto mutex interface
**
** lecnet network library
** Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
**
*******************************************************************************
** This file is part of the liblec library which is released under the Creative
** Commons Attribution Non-Commercial 2.0 license (CC-BY-NC 2.0). See the file
** LICENSE.txt or go to https://github.com/alecmus/liblec/blob/master/LICENSE.md
** for full license details.
*/

#pragma once

namespace liblec {
	class auto_mutex;

	/// <summary>
	/// A mutex object with no publicly accessible methods.
	/// Can only be used by the <see cref="auto_mutex"/> class.
	/// </summary>
	class mutex {
	public:
		mutex();
		~mutex();

	private:
		friend auto_mutex;
		class mutex_impl;
		mutex_impl* d_;
	};

	/// <summary>
	/// A mutex class that automatically unlocks the mutex when it's out of scope.
	/// </summary>
	/// 
	/// <remarks>
	/// Usage example to prevent multiple threads from accessing a function at the same moment:
	/// 
	/// liblec::mutex print_mutex;
	/// 
	/// void print() {
	///		liblec::auto_mutex lock(print_mutex);
	/// 
	///		// do printing
	/// 
	///		return;
	/// }
	/// 
	/// </remarks>
	class auto_mutex {
	public:
		auto_mutex(mutex& mtx);
		~auto_mutex();

	private:
		class auto_mutex_impl;
		auto_mutex_impl* d_;
	};
}
