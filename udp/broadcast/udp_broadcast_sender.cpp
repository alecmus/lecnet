//
// udp_broadcast_sender.cpp - udp broadcast sender implementation
//
// lecnet network library, part of the liblec library
// Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
//
// Released under the CC-BY-NC 2.0 license. For full details see the file
// LICENSE.txt or go to https://github.com/alecmus/liblec/blob/master/LICENSE.md
//

#if not defined(_WINSOCKAPI_)
	#define _WINSOCKAPI_	// prevent winsock 1 from being defined
#endif

#include "../../udp.h"
#include "../../auto_mutex/auto_mutex.h"

#include <future>

#define ASIO_STANDALONE

#if not defined(_WIN32_WINNT)
	#define _WIN32_WINNT 0x0601
#endif

#if defined(_WINSOCKAPI_)
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

class _sender {
public:
	_sender(boost::asio::io_service& io_service,
		unsigned short broadcast_port, std::string message,
		unsigned long max_count, long long timeout_milliseconds) :

		_endpoint(boost::asio::ip::address_v4::broadcast(), broadcast_port),
		_socket(io_service),
		_timer(io_service),
		_message_count(0),
		_message(message),
		_max_count(max_count),
		_timeout_milliseconds(timeout_milliseconds) {

		_message_count++;

		boost::system::error_code error;
		_socket.open(boost::asio::ip::udp::v4(), error);

		if (!error) {
			_socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));
			_socket.set_option(boost::asio::socket_base::broadcast(true));

			_socket.async_send_to(boost::asio::buffer(_message), _endpoint,
				boost::bind(&_sender::handle_send_to, this, boost::asio::placeholders::error));
		}
	}

	~_sender() {
		_socket.close();
	}

	void handle_send_to(const boost::system::error_code& error) {
		if (!error && _message_count < _max_count) {
			_timer.expires_from_now(boost::posix_time::milliseconds(_timeout_milliseconds));
			_timer.async_wait(
				boost::bind(&_sender::handle_timeout, this, boost::asio::placeholders::error));
		}
	}

	void handle_timeout(const boost::system::error_code& error) {
		if (!error) {
			_message_count++;

			_socket.async_send_to(boost::asio::buffer(_message), _endpoint,
				boost::bind(&_sender::handle_send_to, this, boost::asio::placeholders::error));
		}
	}

	int getmessagecount() {
		return _message_count;
	}

private:
	boost::asio::ip::udp::endpoint _endpoint;
	boost::asio::ip::udp::socket _socket;
	boost::asio::deadline_timer _timer;
	const std::string _message;
	long long _timeout_milliseconds;
	unsigned long _message_count;
	unsigned long _max_count;
};

class liblec::lecnet::udp::broadcast::sender::sender_impl {
public:
	sender_impl(unsigned short broadcast_port) :
		_broadcast_port(broadcast_port) {}
	~sender_impl() {}

private:
	friend sender;
	unsigned short _broadcast_port;

	struct send_info {
		std::string message;
		unsigned long max_count = 0;
		long long timeout_milliseconds = 0;
	};

	send_info _send_info;

	std::future<void> _fut;
	static void sender_func(sender* p_current);

	struct result {
		bool _result = false;
		unsigned long _result_count = 0;
		std::string _result_error;
	};

	result _result;
	liblec::mutex _result_lock;
};

liblec::lecnet::udp::broadcast::sender::sender(unsigned short broadcast_port) {
	_d = new sender_impl(broadcast_port);
}

liblec::lecnet::udp::broadcast::sender::~sender() {
	// ensure the async operation is completed before deleting
	if (_d->_fut.valid())
		_d->_fut.get();

	delete _d;
	_d = nullptr;
}

bool liblec::lecnet::udp::broadcast::sender::send(const std::string& message,
	unsigned long max_count,
	long long timeout_milliseconds,
	unsigned long& actual_count,
	std::string& error) {
	actual_count = 0;

	try {
		boost::asio::io_service io_service;

		_sender s(io_service,
			_d->_broadcast_port,
			message, max_count,
			timeout_milliseconds);

		io_service.run();

		actual_count = s.getmessagecount();
		return true;
	}
	catch (std::exception & e) {
		error = e.what();
		return false;
	}
}

void liblec::lecnet::udp::broadcast::sender::sender_impl::sender_func(sender* p_current) {
	bool result = false;
	std::string error;
	unsigned long actual_count = 0;

	try {
		// send broadcast (blocking call)
		result = p_current->send(p_current->_d->_send_info.message,
			p_current->_d->_send_info.max_count, p_current->_d->_send_info.timeout_milliseconds,
			actual_count, error);
	}
	catch (std::exception & e) {
		error = e.what();
	}

	{
		liblec::auto_mutex lock(p_current->_d->_result_lock);
		p_current->_d->_result._result = result;
		p_current->_d->_result._result_count = actual_count;
		p_current->_d->_result._result_error = error;
	}
}

bool liblec::lecnet::udp::broadcast::sender::send_async(const std::string& message,
	const unsigned long& max_count,
	const long long& timeout_milliseconds,
	std::string& error) {
	if (sending()) {
		// allow only one thread
		return true;
	}

	try {
		_d->_send_info.message = message;
		_d->_send_info.max_count = max_count;
		_d->_send_info.timeout_milliseconds = timeout_milliseconds;

		{
			liblec::auto_mutex lock(_d->_result_lock);
			_d->_result._result = false;
			_d->_result._result_count = 0;
			_d->_result._result_error.clear();
		}

		// run sender task asynchronously
		_d->_fut = std::async(std::launch::async,
			_d->sender_func, this);
	}
	catch (std::exception & e) {
		error = e.what();
		return false;
	}

	return true;
}

bool liblec::lecnet::udp::broadcast::sender::sending() {
	if (_d->_fut.valid())
		return _d->_fut.wait_for(std::chrono::seconds{ 0 }) != std::future_status::ready;
	else
		return false;
}

bool liblec::lecnet::udp::broadcast::sender::result(unsigned long& actual_count,
	std::string& error) {
	liblec::auto_mutex lock(_d->_result_lock);

	bool result = _d->_result._result;
	actual_count = _d->_result._result_count;
	error = _d->_result._result_error;

	_d->_result._result = false;
	_d->_result._result_count = 0;
	_d->_result._result_error.clear();

	return result;
}
