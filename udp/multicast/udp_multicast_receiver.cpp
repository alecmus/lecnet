//
// udp_multicast_receiver.cpp - udp multicast receiver implementation
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
	#include <boost/thread.hpp>
	#define _WINSOCKAPI_
#else
	#include <boost/asio.hpp>
	#include <boost/bind.hpp>
	#include <boost/thread.hpp>
#endif

//----------------------------------------------------------------------

//
// This class manages socket timeouts by applying the concept of a deadline.
// Each asynchronous operation is given a deadline by which it must complete.
// Deadlines are enforced by an "actor" that persists for the lifetime of the
// client object:
//
//  +----------------+
//  |                |     
//  | check_deadline |<---+
//  |                |    |
//  +----------------+    | async_wait()
//              |         |
//              +---------+
//
// If the actor determines that the deadline has expired, any outstanding
// socket operations are cancelled. The socket operations themselves are
// implemented as transient actors:
//
//   +---------------+
//   |               |
//   |    receive    |
//   |               |
//   +---------------+
//           |
//  async_-  |    +----------------+
// receive() |    |                |
//           +--->| handle_receive |
//                |                |
//                +----------------+
//
// The client object runs the io_service to block thread execution until the
// actor completes.
//

class _client {
public:
	_client(boost::asio::io_service& io_service,
		const boost::asio::ip::address& listen_address,
		const boost::asio::ip::address& multicast_address,
		unsigned short multicast_port,
		long long timeout_milliseconds) :

		_listen_address(listen_address),
		_multicast_address(multicast_address),
		_multicast_port(multicast_port),
		_timeout_milliseconds(timeout_milliseconds),
		_io_service(&io_service),
		_socket(io_service),
		_deadline(io_service) {}

	bool receive(std::string& message, std::string& error) {
		// Create the socket so that multiple may be bound to the same address.
		boost::asio::ip::udp::endpoint listen_endpoint(_listen_address,
			_multicast_port);
		_socket.open(listen_endpoint.protocol());
		_socket.set_option(boost::asio::ip::udp::socket::reuse_address(true));
		_socket.bind(listen_endpoint);

		// Join the multicast group.
		_socket.set_option(boost::asio::ip::multicast::join_group(_multicast_address));

		// No deadline is required until the first socket operation is started. We
		// set the deadline to positive infinity so that the actor takes no action
		// until a specific deadline is set.
		_deadline.expires_at(boost::posix_time::pos_infin);

		// Start the persistent actor that checks for deadline expiry.
		check_deadline();

		boost::system::error_code ec;
		std::size_t n = do_receive(boost::asio::buffer(_data),
			boost::posix_time::milliseconds(_timeout_milliseconds),
			ec);

		bool result;

		if (ec) {
			error = ec.message();
			result = false;
		}
		else {
			std::stringstream ss;
			ss.write(_data, n);
			message = ss.str();
			result = true;
		}

		try {
			// close the socket if it's still open
			if (_socket.is_open()) {
				_socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);

				_socket.close();
			}
		}
		catch (const std::exception&) {
			// ignore this if it occurs ... the underlying descriptor is closed anyway
		}

		// stop the service, if it's still running
		if (!_io_service->stopped())
			_io_service->stop();

		return result;
	}

	void stop() {
		if (_socket.is_open())
			_deadline.expires_from_now(boost::posix_time::milliseconds(0));
	}

private:
	std::size_t do_receive(const boost::asio::mutable_buffer& buffer,
		boost::posix_time::time_duration timeout,
		boost::system::error_code& ec) {
		// Set a deadline for the asynchronous operation.
		_deadline.expires_from_now(timeout);

		// Set up the variables that receive the result of the asynchronous
		// operation. The error code is set to would_block to signal that the
		// operation is incomplete. Asio guarantees that its asynchronous
		// operations will never fail with would_block, so any other value in
		// ec indicates completion.
		ec = boost::asio::error::would_block;
		std::size_t length = 0;

		// Start the asynchronous operation itself. The handle_receive function
		// used as a callback will update the ec and length variables.
		_socket.async_receive(boost::asio::buffer(buffer),
			boost::bind(&_client::handle_receive, _1, _2, &ec, &length));

		// Block until the asynchronous operation has completed.
		do _io_service->run_one(); while (ec == boost::asio::error::would_block);

		return length;
	}

	static void handle_receive( const boost::system::error_code& ec, std::size_t length,
		boost::system::error_code* out_ec, std::size_t* out_length) {
		*out_ec = ec;
		*out_length = length;
	}

	void check_deadline() {
		// Check whether the deadline has passed. We compare the deadline against
		// the current time since a new asynchronous operation may have moved the
		// deadline before this actor had a chance to run.
		if (_deadline.expires_at() <= boost::asio::deadline_timer::traits_type::now()) {
			// The deadline has passed. The outstanding asynchronous operation needs
			// to be cancelled so that the blocked receive() function will return.
			//
			// Please note that cancel() has portability issues on some versions of
			// Microsoft Windows, and it may be necessary to use close() instead.
			// Consult the documentation for cancel() for further information.
			_socket.cancel();

			// There is no longer an active deadline. The expiry is set to positive
			// infinity so that the actor takes no action until a new deadline is set.
			_deadline.expires_at(boost::posix_time::pos_infin);
		}

		// Put the actor back to sleep.
		_deadline.async_wait(boost::bind(&_client::check_deadline, this));
	}

private:
	boost::asio::deadline_timer _deadline;
	boost::asio::io_service* _io_service;
	boost::asio::ip::address _listen_address;
	boost::asio::ip::address _multicast_address;
	unsigned short _multicast_port;
	long long _timeout_milliseconds;

private:
	boost::asio::ip::udp::socket _socket;
	boost::asio::ip::udp::endpoint _sender_endpoint;
	enum { max_length = 1024 };
	char _data[max_length];
};

///////////////////////////////////////////////////////////////////////////////////////////////////

/// <summary>
/// Structure for receiver results.
/// </summary>
struct receive_result {
	/// <summary>
	/// The receive result. True if successful, else false.
	/// </summary>
	bool result = false;

	/// <summary>
	/// Error information, in the case that <see cref="result"/> is false.
	/// </summary>
	std::string error;

	/// <summary>
	/// The received message, in the case that <see cref="result"/> is true.
	/// </summary>
	std::string message;
};

class liblec::lecnet::udp::multicast::receiver::receiver_impl {
public:
	receiver_impl(unsigned short port,
		std::string multicast_address,
		std::string listen_address) :

		_port(port),
		_multicast_address(multicast_address),
		_listen_address(listen_address),
		_p_current_client(nullptr) {}

	~receiver_impl() {}

	static void receiver_func(receiver* p_current);

private:
	std::future<void> _fut;
	_client* _p_current_client;
	unsigned short _port;
	std::string _multicast_address;
	std::string _listen_address;
	long long _timeout_milliseconds;

	// for capturing the result of the the receiver thread
	receive_result _result;
	liblec::mutex _result_lock;

	friend receiver;
};

liblec::lecnet::udp::multicast::receiver::receiver(unsigned short multicast_port,
	std::string multicast_address,
	std::string listen_address) {
	_d = new receiver_impl(multicast_port,
		multicast_address,
		listen_address);
}

liblec::lecnet::udp::multicast::receiver::~receiver() {
	stop();

	// ensure the async operation is completed before deleting
	if (_d->_fut.valid())
		_d->_fut.get();

	delete _d;
	_d = nullptr;
}

void liblec::lecnet::udp::multicast::receiver::receiver_impl::receiver_func(receiver* p_current) {
	try {
		boost::asio::io_service io_service;
		_client client(io_service,
			boost::asio::ip::address::from_string(p_current->_d->_listen_address),
			boost::asio::ip::address::from_string(p_current->_d->_multicast_address),
			p_current->_d->_port, p_current->_d->_timeout_milliseconds);

		p_current->_d->_p_current_client = &client;

		// run the client
		std::string message, error;
		bool result = client.receive(message, error);

		p_current->_d->_p_current_client = nullptr;

		// only here can _result be changed to true. Only here. This is absolutely important.
		liblec::auto_mutex lock(p_current->_d->_result_lock);
		p_current->_d->_result.result = result;
		p_current->_d->_result.error = error;
		p_current->_d->_result.message = message;
	}
	catch (std::exception& e) {
		liblec::auto_mutex lock(p_current->_d->_result_lock);
		p_current->_d->_result.result = false;
		p_current->_d->_result.error = e.what();
		p_current->_d->_result.message.clear();
	}
}

bool liblec::lecnet::udp::multicast::receiver::run(long long timeout_milliseconds,
	std::string& error) {
	if (running()) {
		// allow only one thread
		return true;
	}

	_d->_timeout_milliseconds = timeout_milliseconds;

	try {
		// run receiver task asynchronously
		_d->_fut = std::async(std::launch::async,
			_d->receiver_func, this);
	}
	catch (std::exception& e) {
		error = e.what();
		return false;
	}

	return true;
}

bool liblec::lecnet::udp::multicast::receiver::running() {
	if (_d->_fut.valid())
		return _d->_fut.wait_for(std::chrono::seconds{ 0 }) != std::future_status::ready;
	else
		return false;
}

bool liblec::lecnet::udp::multicast::receiver::get(std::string& message,
	std::string& error) {
	liblec::auto_mutex lock(_d->_result_lock);

	// capture the result
	bool result = _d->_result.result;
	error = _d->_result.error;
	message = _d->_result.message;

	// reset the result
	_d->_result.result = false;
	_d->_result.error.clear();
	_d->_result.message.clear();

	return result;
}

void liblec::lecnet::udp::multicast::receiver::stop() {
	try {
		if (running()) {
			if (_d->_p_current_client)
				_d->_p_current_client->stop();	// to-do: make this safer

			// wait for receiver to stop running
			while (running())
				boost::this_thread::sleep(boost::posix_time::milliseconds(1));
		}
	}
	catch (std::exception&) {}
}
