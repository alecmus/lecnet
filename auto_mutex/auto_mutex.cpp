/*
** auto_mutex.cpp - auto mutex implementation
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
		mtx_.lock();
	}

	void unlock() {
		mtx_.unlock();
	}

	std::mutex mtx_;
};

liblec::mutex::mutex() {
	d_ = new mutex_impl;
}

liblec::mutex::~mutex() {
	if (d_) {
		delete d_;
		d_ = nullptr;
	}
}

class liblec::auto_mutex::auto_mutex_impl {
public:
	auto_mutex_impl(mutex& mtx) :
		p_mtx_(&mtx) {
		p_mtx_->d_->lock();
	}

	~auto_mutex_impl() {
		p_mtx_->d_->unlock();
	}

private:
	mutex* p_mtx_;
};

liblec::auto_mutex::auto_mutex(mutex& mtx) {
	d_ = new auto_mutex_impl(mtx);
}

liblec::auto_mutex::~auto_mutex() {
	if (d_) {
		delete d_;
		d_ = nullptr;
	}
}
