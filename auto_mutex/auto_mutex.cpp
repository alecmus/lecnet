//
// auto_mutex.cpp - auto mutex implementation
//
// lecnet network library, part of the liblec library
// Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
//
// Released under the CC-BY-NC 2.0 license. For full details see the file
// LICENSE.txt or go to https://github.com/alecmus/liblec/blob/master/LICENSE.md
//

#include "auto_mutex.h"
#include <mutex>

class mutex;

/// <summary>
/// Wrapper for the std::mutex object.
/// </summary>
class liblec::mutex::mutex_impl {
public:
	mutex_impl() {}
	~mutex_impl() {}

	void lock() {
		_mtx.lock();
	}

	void unlock() {
		_mtx.unlock();
	}

	std::mutex _mtx;
};

liblec::mutex::mutex() {
	_d = new mutex_impl;
}

liblec::mutex::~mutex() {
	if (_d) {
		delete _d;
		_d = nullptr;
	}
}

class liblec::auto_mutex::auto_mutex_impl {
public:
	auto_mutex_impl(mutex& mtx) :
		_p_mtx(&mtx) {
		_p_mtx->_d->lock();
	}

	~auto_mutex_impl() {
		_p_mtx->_d->unlock();
	}

private:
	mutex* _p_mtx;
};

liblec::auto_mutex::auto_mutex(mutex& mtx) {
	_d = new auto_mutex_impl(mtx);
}

liblec::auto_mutex::~auto_mutex() {
	if (_d) {
		delete _d;
		_d = nullptr;
	}
}
