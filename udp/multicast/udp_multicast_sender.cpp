/*
** udp_multicast_sender.cpp - udp multicast sender implementation
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

#ifndef _WINSOCKAPI_
#define _WINSOCKAPI_	// prevent winsock 1 from being defined
#endif

#include "../../udp.h"
#include "../../auto_mutex/auto_mutex.h"

#include <future>

#define ASIO_STANDALONE

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#ifdef _WINSOCKAPI_
#undef _WINSOCKAPI_
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#define _WINSOCKAPI_
#else
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#endif

class sender_ {
public:
	sender_(boost::asio::io_service& io_service,
		const boost::asio::ip::address& multicast_address,
		unsigned short multicast_port, std::string message,
		unsigned long max_count, long long timeout_milliseconds) :

		endpoint_(multicast_address, multicast_port),
		socket_(io_service, endpoint_.protocol()),
		timer_(io_service),
		message_count_(0),
		message_(message),
		max_count_(max_count),
		timeout_milliseconds_(timeout_milliseconds) {

		message_count_++;

		socket_.async_send_to(boost::asio::buffer(message_), endpoint_,
			boost::bind(&sender_::handle_send_to, this, boost::asio::placeholders::error));
	}

	void handle_send_to(const boost::system::error_code& error) {
		if (!error && message_count_ < max_count_) {
			timer_.expires_from_now(boost::posix_time::milliseconds(timeout_milliseconds_));
			timer_.async_wait(
				boost::bind(&sender_::handle_timeout, this, boost::asio::placeholders::error));
		}
	}

	void handle_timeout(const boost::system::error_code& error) {
		if (!error) {
			message_count_++;

			socket_.async_send_to(boost::asio::buffer(message_), endpoint_,
				boost::bind(&sender_::handle_send_to, this, boost::asio::placeholders::error));
		}
	}

	int getmessagecount() {
		return message_count_;
	}

private:
	boost::asio::ip::udp::endpoint endpoint_;
	boost::asio::ip::udp::socket socket_;
	boost::asio::deadline_timer timer_;
	const std::string message_;
	long long timeout_milliseconds_;
	unsigned long message_count_;
	unsigned long max_count_;
};

class liblec::lecnet::udp::multicast::sender::sender_impl {
public:
	sender_impl(unsigned short multicast_port,
		std::string multicast_address) :

		multicast_port_(multicast_port),
		multicast_address_(multicast_address) {}

	~sender_impl() {}

private:
	friend sender;
	unsigned short multicast_port_;
	std::string multicast_address_;

	struct send_info {
		std::string message;
		unsigned long max_count = 0;
		long long timeout_milliseconds = 0;
	};

	send_info send_info_;

	std::future<void> fut_;
	static void sender_func(sender* p_current);

	struct result {
		bool result_ = false;
		unsigned long result_count_ = 0;
		std::string result_error_;
	};

	result result_;
	liblec::mutex result_lock_;
};

liblec::lecnet::udp::multicast::sender::sender(unsigned short multicast_port,
	std::string multicast_address) {
	d_ = new sender_impl(multicast_port, multicast_address);
}

liblec::lecnet::udp::multicast::sender::~sender() {
	// ensure the async operation is completed before deleting
	if (d_->fut_.valid())
		d_->fut_.get();

	delete d_;
	d_ = nullptr;
}

bool liblec::lecnet::udp::multicast::sender::send(const std::string& message,
	unsigned long max_count,
	long long timeout_milliseconds,
	unsigned long& actual_count,
	std::string& error) {
	actual_count = 0;

	try {
		boost::asio::io_service io_service;

		sender_ s(io_service,
			boost::asio::ip::address::from_string(d_->multicast_address_),
			d_->multicast_port_,
			message, max_count,
			timeout_milliseconds);

		io_service.run();

		actual_count = s.getmessagecount();
		return true;
	}
	catch (std::exception& e) {
		error = e.what();
		return false;
	}
}

void liblec::lecnet::udp::multicast::sender::sender_impl::sender_func(sender* p_current) {
	bool result = false;
	std::string error;
	unsigned long actual_count = 0;

	try {
		// send multicast (blocking call)
		result = p_current->send(p_current->d_->send_info_.message,
			p_current->d_->send_info_.max_count, p_current->d_->send_info_.timeout_milliseconds,
			actual_count, error);
	}
	catch (std::exception& e) {
		error = e.what();
	}

	{
		liblec::auto_mutex lock(p_current->d_->result_lock_);
		p_current->d_->result_.result_ = result;
		p_current->d_->result_.result_count_ = actual_count;
		p_current->d_->result_.result_error_ = error;
	}
}

bool liblec::lecnet::udp::multicast::sender::send_async(const std::string& message,
	const unsigned long& max_count,
	const long long& timeout_milliseconds,
	std::string& error) {
	if (sending()) {
		// allow only one thread
		return true;
	}

	try {
		d_->send_info_.message = message;
		d_->send_info_.max_count = max_count;
		d_->send_info_.timeout_milliseconds = timeout_milliseconds;

		{
			liblec::auto_mutex lock(d_->result_lock_);
			d_->result_.result_ = false;
			d_->result_.result_count_ = 0;
			d_->result_.result_error_.clear();
		}

		// run sender task asynchronously
		d_->fut_ = std::async(std::launch::async,
			d_->sender_func, this);
	}
	catch (std::exception& e) {
		error = e.what();
		return false;
	}

	return true;
}

bool liblec::lecnet::udp::multicast::sender::sending() {
	if (d_->fut_.valid())
		return d_->fut_.wait_for(std::chrono::seconds{ 0 }) != std::future_status::ready;
	else
		return false;
}

bool liblec::lecnet::udp::multicast::sender::result(unsigned long& actual_count,
	std::string& error) {
	liblec::auto_mutex lock(d_->result_lock_);

	bool result = d_->result_.result_;
	actual_count = d_->result_.result_count_;
	error = d_->result_.result_error_;

	d_->result_.result_ = false;
	d_->result_.result_count_ = 0;
	d_->result_.result_error_.clear();

	return result;
}
