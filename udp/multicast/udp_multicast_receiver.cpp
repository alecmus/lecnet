/*
** udp_multicast_receiver.cpp - udp multicast receiver implementation
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

class client_ {
public:
	client_(boost::asio::io_service& io_service,
		const boost::asio::ip::address& listen_address,
		const boost::asio::ip::address& multicast_address,
		unsigned short multicast_port,
		long long timeout_milliseconds) :

		listen_address_(listen_address),
		multicast_address_(multicast_address),
		multicast_port_(multicast_port),
		timeout_milliseconds_(timeout_milliseconds),
		io_service_(&io_service),
		socket_(io_service),
		deadline_(io_service) {}

	bool receive(std::string& message, std::string& error) {
		// Create the socket so that multiple may be bound to the same address.
		boost::asio::ip::udp::endpoint listen_endpoint(listen_address_,
			multicast_port_);
		socket_.open(listen_endpoint.protocol());
		socket_.set_option(boost::asio::ip::udp::socket::reuse_address(true));
		socket_.bind(listen_endpoint);

		// Join the multicast group.
		socket_.set_option(boost::asio::ip::multicast::join_group(multicast_address_));

		// No deadline is required until the first socket operation is started. We
		// set the deadline to positive infinity so that the actor takes no action
		// until a specific deadline is set.
		deadline_.expires_at(boost::posix_time::pos_infin);

		// Start the persistent actor that checks for deadline expiry.
		check_deadline();

		boost::system::error_code ec;
		std::size_t n = do_receive(boost::asio::buffer(data_),
			boost::posix_time::milliseconds(timeout_milliseconds_),
			ec);

		bool result;

		if (ec) {
			error = ec.message();
			result = false;
		}
		else {
			std::stringstream ss;
			ss.write(data_, n);
			message = ss.str();
			result = true;
		}

		try {
			// close the socket if it's still open
			if (socket_.is_open()) {
				socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);

				socket_.close();
			}
		}
		catch (const std::exception&) {
			// ignore this if it occurs ... the underlying descriptor is closed anyway
		}

		// stop the service, if it's still running
		if (!io_service_->stopped())
			io_service_->stop();

		return result;
	}

	void stop() {
		if (socket_.is_open())
			deadline_.expires_from_now(boost::posix_time::milliseconds(0));
	}

private:
	std::size_t do_receive(const boost::asio::mutable_buffer& buffer,
		boost::posix_time::time_duration timeout,
		boost::system::error_code& ec) {
		// Set a deadline for the asynchronous operation.
		deadline_.expires_from_now(timeout);

		// Set up the variables that receive the result of the asynchronous
		// operation. The error code is set to would_block to signal that the
		// operation is incomplete. Asio guarantees that its asynchronous
		// operations will never fail with would_block, so any other value in
		// ec indicates completion.
		ec = boost::asio::error::would_block;
		std::size_t length = 0;

		// Start the asynchronous operation itself. The handle_receive function
		// used as a callback will update the ec and length variables.
		socket_.async_receive(boost::asio::buffer(buffer),
			boost::bind(&client_::handle_receive, _1, _2, &ec, &length));

		// Block until the asynchronous operation has completed.
		do io_service_->run_one(); while (ec == boost::asio::error::would_block);

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
		if (deadline_.expires_at() <= boost::asio::deadline_timer::traits_type::now()) {
			// The deadline has passed. The outstanding asynchronous operation needs
			// to be cancelled so that the blocked receive() function will return.
			//
			// Please note that cancel() has portability issues on some versions of
			// Microsoft Windows, and it may be necessary to use close() instead.
			// Consult the documentation for cancel() for further information.
			socket_.cancel();

			// There is no longer an active deadline. The expiry is set to positive
			// infinity so that the actor takes no action until a new deadline is set.
			deadline_.expires_at(boost::posix_time::pos_infin);
		}

		// Put the actor back to sleep.
		deadline_.async_wait(boost::bind(&client_::check_deadline, this));
	}

private:
	boost::asio::deadline_timer deadline_;
	boost::asio::io_service* io_service_;
	boost::asio::ip::address listen_address_;
	boost::asio::ip::address multicast_address_;
	unsigned short multicast_port_;
	long long timeout_milliseconds_;

private:
	boost::asio::ip::udp::socket socket_;
	boost::asio::ip::udp::endpoint sender_endpoint_;
	enum { max_length = 1024 };
	char data_[max_length];
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

		port_(port),
		multicast_address_(multicast_address),
		listen_address_(listen_address),
		p_current_client_(nullptr) {}

	~receiver_impl() {}

	static void receiver_func(receiver* p_current);

private:
	std::future<void> fut_;
	client_* p_current_client_;
	unsigned short port_;
	std::string multicast_address_;
	std::string listen_address_;
	long long timeout_milliseconds_;

	// for capturing the result of the the receiver thread
	receive_result result_;
	liblec::mutex result_lock_;

	friend receiver;
};

liblec::lecnet::udp::multicast::receiver::receiver(unsigned short multicast_port,
	std::string multicast_address,
	std::string listen_address) {
	d_ = new receiver_impl(multicast_port,
		multicast_address,
		listen_address);
}

liblec::lecnet::udp::multicast::receiver::~receiver() {
	stop();

	// ensure the async operation is completed before deleting
	if (d_->fut_.valid())
		d_->fut_.get();

	delete d_;
	d_ = nullptr;
}

void liblec::lecnet::udp::multicast::receiver::receiver_impl::receiver_func(receiver* p_current) {
	try {
		boost::asio::io_service io_service;
		client_ client(io_service,
			boost::asio::ip::address::from_string(p_current->d_->listen_address_),
			boost::asio::ip::address::from_string(p_current->d_->multicast_address_),
			p_current->d_->port_, p_current->d_->timeout_milliseconds_);

		p_current->d_->p_current_client_ = &client;

		// run the client
		std::string message, error;
		bool result = client.receive(message, error);

		p_current->d_->p_current_client_ = nullptr;

		// only here can result_ be changed to true. Only here. This is absolutely important.
		liblec::auto_mutex lock(p_current->d_->result_lock_);
		p_current->d_->result_.result = result;
		p_current->d_->result_.error = error;
		p_current->d_->result_.message = message;
	}
	catch (std::exception& e) {
		liblec::auto_mutex lock(p_current->d_->result_lock_);
		p_current->d_->result_.result = false;
		p_current->d_->result_.error = e.what();
		p_current->d_->result_.message.clear();
	}
}

bool liblec::lecnet::udp::multicast::receiver::run(long long timeout_milliseconds,
	std::string& error) {
	if (running()) {
		// allow only one thread
		return true;
	}

	d_->timeout_milliseconds_ = timeout_milliseconds;

	try {
		// run receiver task asynchronously
		d_->fut_ = std::async(std::launch::async,
			d_->receiver_func, this);
	}
	catch (std::exception& e) {
		error = e.what();
		return false;
	}

	return true;
}

bool liblec::lecnet::udp::multicast::receiver::running() {
	if (d_->fut_.valid())
		return d_->fut_.wait_for(std::chrono::seconds{ 0 }) != std::future_status::ready;
	else
		return false;
}

bool liblec::lecnet::udp::multicast::receiver::get(std::string& message,
	std::string& error) {
	liblec::auto_mutex lock(d_->result_lock_);

	// capture the result
	bool result = d_->result_.result;
	error = d_->result_.error;
	message = d_->result_.message;

	// reset the result
	d_->result_.result = false;
	d_->result_.error.clear();
	d_->result_.message.clear();

	return result;
}

void liblec::lecnet::udp::multicast::receiver::stop() {
	try {
		if (running()) {
			if (d_->p_current_client_)
				d_->p_current_client_->stop();	// to-do: make this safer

			// wait for receiver to stop running
			while (running())
				boost::this_thread::sleep(boost::posix_time::milliseconds(1));
		}
	}
	catch (std::exception&) {}
}
