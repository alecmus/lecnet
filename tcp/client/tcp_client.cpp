/*
** tcp_client.cpp - tcp/ip client implementation
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

#if not defined(_WINSOCKAPI_)
	#define _WINSOCKAPI_	// prevent winsock 1 from being defined
#endif

#include "../../tcp.h"
#include "../../auto_mutex/auto_mutex.h"
#include "../../helper_fxns/helper_fxns.h"

#include <future>

#define _CRT_SECURE_NO_WARNINGS
#define ASIO_STANDALONE

#if not defined(_WIN32_WINNT)
	#define _WIN32_WINNT 0x0601
#endif

#if defined(_WINSOCKAPI_)
	#undef _WINSOCKAPI_
	#include <boost/bind.hpp>
	#include <boost/asio.hpp>
	#include <boost/asio/ssl.hpp>
	#include <boost/thread.hpp>
	#define _WINSOCKAPI_
#else
	#include <boost/bind.hpp>
	#include <boost/asio.hpp>
	#include <boost/asio/ssl.hpp>
	#include <boost/thread.hpp>
#endif

#undef _CRT_SECURE_NO_WARNINGS

// typedefs to simplify code
typedef boost::asio::ip::tcp::socket plain_socket;	// plain socket
typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;	// secure socket

/// <summary>
/// TCP iterator.
/// </summary>
/// 
/// <remarks>
/// To solve compile issue, solution found here: https://svn.boost.org/trac/boost/ticket/12115
/// </remarks>
typedef boost::asio::ip::tcp::resolver::iterator tcp_iterator;

/// <summary>
/// Structure for connet results.
/// </summary>
struct connect_result {
	/// <summary>
	/// The connect result. True if successful, else false.
	/// </summary>
	bool connected = false;

	/// <summary>
	/// Error information, in the case that <see cref="result"/> is false.
	/// </summary>
	std::string error;
}; // connect_result

struct received_data {
	bool received = false;
	std::string data = "";
	std::string error;
};

struct send_info {
	unsigned long data_id;
	std::string data;
	long timeout_seconds;
	std::future<void> fut;

	bool result;
	std::string received;
	std::string error;
};

class liblec::lecnet::tcp::client::impl {
public:
	impl() {};
	~impl() {};

	static void client_func(liblec::lecnet::tcp::client* p_current);

	void do_send_data(const std::string& raw_to_send,
		unsigned long id);

	static void send_func(unsigned long data_id,
		client* p_current);

	std::future<void> fut_;
	boost::asio::io_service* p_io_service_ = nullptr;
	void* p_socket_ = nullptr;

	long timeout_seconds_;
	std::string address_;
	unsigned short port_;
	bool use_ssl_;
	std::string ca_cert_path_;

	// in-class message ID tracker to ensure each message is sent with a unique ID
	unsigned long message_id_ = 0;
	unsigned long data_id_ = 0;

	std::string error_;
	liblec::mutex error_lock_;

	connect_result result_;
	liblec::mutex result_lock_;

	// Map for data received from the server. Key is the message ID and value is the data.
	std::map<unsigned long, received_data> data_;
	liblec::mutex data_lock_;

	std::map<unsigned long, send_info> send_queue_;
	liblec::mutex send_queue_lock_;

	liblec::lecnet::network_traffic traffic_;
	liblec::mutex traffic_lock_;

	bool connecting_ = false;
	liblec::mutex connecting_lock_;

	unsigned long magic_number_ = 0;

	friend client;
};

class liblec::lecnet::tcp::client::client_async_ssl {
public:
	client_async_ssl(liblec::lecnet::tcp::client* p_this_client,
		boost::asio::io_service* pio_service,
		boost::asio::ssl::context& context,
		tcp_iterator endpoint_iterator)
		: socket_(*pio_service, context),
		p_this_client_(p_this_client),
		deadline_(*pio_service),
		stopped_(false) {

		socket_.set_verify_mode(boost::asio::ssl::verify_peer);
		socket_.set_verify_callback(
			boost::bind(&client_async_ssl::verify_certificate, this, _1, _2));

		boost::asio::async_connect(socket_.lowest_layer(), endpoint_iterator,
			boost::bind(&client_async_ssl::handle_connect, this,
				boost::asio::placeholders::error));

		/*
		** Start the deadline actor. You will note that we're not setting any
		** particular deadline here. Instead, the connect and input actors will
		** update the deadline prior to each asynchronous operation or as desired.
		*/
		deadline_.async_wait(boost::bind(&client_async_ssl::check_deadline, this));
	}

	~client_async_ssl() {
		try {
			if (socket().is_open())
				socket().close();

			p_this_client_->d_.p_socket_ = nullptr;
		}
		catch (const std::exception&) {}
	}

	bool verify_certificate(bool preverified,
		boost::asio::ssl::verify_context& ctx) {
		// The verify callback can be used to check whether the certificate that is
		// being presented is valid for the peer. For example, RFC 2818 describes
		// the steps involved in doing this for HTTPS. Consult the OpenSSL
		// documentation for more details. Note that the callback is called once
		// for each certificate in the certificate chain, starting from the root
		// certificate authority.

		char subject_name[256];
		X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
		X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);

		return preverified;
	}

	void handle_connect(const boost::system::error_code& error) {
		if (!error) {
			long time_out = p_this_client_->d_.timeout_seconds_;

			if (time_out > 0) {
				// Set a deadline for the connect operation.
				deadline_.expires_from_now(
					boost::posix_time::seconds(p_this_client_->d_.timeout_seconds_));
			}

			socket_.async_handshake(boost::asio::ssl::stream_base::client,
				boost::bind(&client_async_ssl::handle_handshake, this,
					boost::asio::placeholders::error));
		}
		else {
			{
				liblec::auto_mutex lock(p_this_client_->d_.error_lock_);
				p_this_client_->d_.error_ = "Connect failed: " + error.message();
			}

			stopped_ = true;
			deadline_.cancel();
		}
	}

	void handle_handshake(const boost::system::error_code& error) {
		if (!error) {
			// connected successfully

			// There is no longer an active deadline. The expiry is set to positive
			// infinity so that the actor takes no action until a new deadline is set.
			deadline_.expires_at(boost::posix_time::pos_infin);

			p_this_client_->d_.p_socket_ = &socket_;

			// it's essential to limit the scope of this mutex
			{
				liblec::auto_mutex lock(p_this_client_->d_.result_lock_);
				p_this_client_->d_.result_.connected = true;
				p_this_client_->d_.result_.error.clear();
			}

			// it's essential to limit the scope of this mutex
			{
				liblec::auto_mutex lock(p_this_client_->d_.connecting_lock_);
				p_this_client_->d_.connecting_ = false;
			}

			execute();
		}
		else {
			{
				liblec::auto_mutex lock(p_this_client_->d_.error_lock_);
				p_this_client_->d_.error_ = "Handshake failed: " + error.message();
			}

			stopped_ = true;
			deadline_.cancel();
		}
	}

	// execute entry point
	void execute() {
		// read data
		while (true) {
			boost::system::error_code error;
			size_t bytes_transferred = socket_.read_some(boost::asio::buffer(buffer_, buffer_size),
				error);

			{
				liblec::auto_mutex lock(p_this_client_->d_.traffic_lock_);
				p_this_client_->d_.traffic_.in += bytes_transferred;
			}

			if (!error) {
				received_ += std::string(buffer_, bytes_transferred);

				// retrieve magic number
				if (get_ul_prefix(received_, 1) == p_this_client_->d_.magic_number_) {
					// retrieve embedded length
					unsigned long length = get_ul_prefix(received_, 3);

					if (length == received_.length()) {
						// all data has been received

						// retrieve message ID
						unsigned long message_id = get_ul_prefix(received_, 2);

						// process the data
						process_received_data(received_, message_id);

						// clear
						received_.clear();
					}
					else {
						if (length > received_.length()) {
							// essential to stay connected
						}
						else {
							// invalid data received
							liblec::auto_mutex lock(p_this_client_->d_.error_lock_);
							p_this_client_->d_.error_ = "Invalid data received";
							break;
						}
					}
				}
				else {
					// invalid data received
					liblec::auto_mutex lock(p_this_client_->d_.error_lock_);
					p_this_client_->d_.error_ = "Invalid data received";
					break;
				}
			}
			else {
				// client disconnected
				liblec::auto_mutex lock(p_this_client_->d_.error_lock_);
				p_this_client_->d_.error_ = "Client disconnected from server: " + error.message();
				break;
			}
		}

		stopped_ = true;
		deadline_.cancel();
	}

private:
	void process_received_data(std::string& data,
		unsigned long message_id) {
		// skip magic number
		get_ul_prefix(data);

		// skip message id
		get_ul_prefix(data);

		// skip embedded length
		get_ul_prefix(data);

		liblec::auto_mutex lock(p_this_client_->d_.data_lock_);

		try {
			if (p_this_client_->d_.data_.find(message_id) !=
				p_this_client_->d_.data_.end()) {
				p_this_client_->d_.data_.at(message_id).data = data;
				p_this_client_->d_.data_.at(message_id).received = true;
			}
		}
		catch (std::exception& e) {
			// probably already deleted from map
			liblec::auto_mutex lock(p_this_client_->d_.error_lock_);
			p_this_client_->d_.error_ = "Exception: " + std::string(e.what());
		}
	}

	void check_deadline() {
		if (stopped_)
			return;

		/*
		** Check whether the deadline has passed. We compare the deadline against
		** the current time since a new asynchronous operation may have moved the
		** deadline before this actor had a chance to run.
		*/
		if (deadline_.expires_at() <= boost::asio::deadline_timer::traits_type::now()) {
			/*
			** The deadline has passed. Close socket.
			*/
			socket().shutdown(plain_socket::shutdown_both);
			socket().close();

			/*
			** There is no longer an active deadline. The expiry is set to positive
			** infinity so that the actor takes no action until a new deadline is set.
			*/
			deadline_.expires_at(boost::posix_time::pos_infin);
		}

		// Put the actor back to sleep.
		deadline_.async_wait(boost::bind(&client_async_ssl::check_deadline, this));
	} // check_deadline

	ssl_socket::lowest_layer_type& socket() {
		return socket_.lowest_layer();
	}

	enum { buffer_size = 1024 * 64 };
	char buffer_[buffer_size];

	liblec::lecnet::tcp::client* p_this_client_ = nullptr;

	boost::asio::deadline_timer deadline_;
	std::string received_;
	ssl_socket socket_;
	bool stopped_;
};

class liblec::lecnet::tcp::client::client_async {
public:
	client_async(liblec::lecnet::tcp::client* p_this_client,
		boost::asio::io_service* pio_service,
		tcp_iterator endpoint_iterator)
		: socket_(*pio_service),
		p_this_client_(p_this_client),
		deadline_(*pio_service),
		stopped_(false) {

		boost::asio::async_connect(socket_, endpoint_iterator,
			boost::bind(&client_async::handle_connect, this,
				boost::asio::placeholders::error));

		/*
		** Start the deadline actor. You will note that we're not setting any
		** particular deadline here. Instead, the connect and input actors will
		** update the deadline prior to each asynchronous operation or as desired.
		*/
		deadline_.async_wait(boost::bind(&client_async::check_deadline, this));

		long time_out = p_this_client_->d_.timeout_seconds_;

		if (time_out > 0) {
			// Set a deadline for the connect operation.
			deadline_.expires_from_now(
				boost::posix_time::seconds(p_this_client_->d_.timeout_seconds_));
		}
	}

	~client_async() {
		try {
			if (socket_.is_open())
				socket_.close();

			p_this_client_->d_.p_socket_ = nullptr;
		}
		catch (const std::exception&) {}
	}

	void handle_connect(const boost::system::error_code& error) {
		if (!error) {
			// connected successfully
			// There is no longer an active deadline. The expiry is set to positive
			// infinity so that the actor takes no action until a new deadline is set.
			deadline_.expires_at(boost::posix_time::pos_infin);

			p_this_client_->d_.p_socket_ = &socket_;

			// it's essential to limit the scope of this mutex
			{
				liblec::auto_mutex lock(p_this_client_->d_.result_lock_);
				p_this_client_->d_.result_.connected = true;
				p_this_client_->d_.result_.error.clear();
			}

			// it's essential to limit the scope of this mutex
			{
				liblec::auto_mutex lock(p_this_client_->d_.connecting_lock_);
				p_this_client_->d_.connecting_ = false;
			}

			execute();
		}
		else {
			{
				liblec::auto_mutex lock(p_this_client_->d_.error_lock_);
				p_this_client_->d_.error_ = "Connect failed: " + error.message();
			}

			stopped_ = true;
			deadline_.cancel();
		}
	}

	// execute entry point
	void execute() {
		// read data
		while (true) {
			boost::system::error_code error;
			size_t bytes_transferred = socket_.read_some(boost::asio::buffer(buffer_, buffer_size),
				error);

			{
				liblec::auto_mutex lock(p_this_client_->d_.traffic_lock_);
				p_this_client_->d_.traffic_.in += bytes_transferred;
			}

			if (!error) {
				received_ += std::string(buffer_, bytes_transferred);

				// retrieve magic number
				if (get_ul_prefix(received_, 1) == p_this_client_->d_.magic_number_) {
					// retrieve embedded length
					unsigned long length = get_ul_prefix(received_, 3);

					if (length == received_.length()) {
						// all data has been received

						// retrieve message ID
						unsigned long message_id = get_ul_prefix(received_, 2);

						// process the data
						process_received_data(received_, message_id);

						// clear
						received_.clear();
					}
					else {
						if (length > received_.length()) {
							// essential to stay connected
						}
						else {
							// invalid data received
							liblec::auto_mutex lock(p_this_client_->d_.error_lock_);
							p_this_client_->d_.error_ = "Invalid data received";
							break;
						}
					}
				}
				else {
					// invalid data received
					liblec::auto_mutex lock(p_this_client_->d_.error_lock_);
					p_this_client_->d_.error_ = "Invalid data received";
					break;
				}
			}
			else {
				// client disconnected
				liblec::auto_mutex lock(p_this_client_->d_.error_lock_);
				p_this_client_->d_.error_ = "Client disconnected from server: " + error.message();
				break;
			}
		}

		stopped_ = true;
		deadline_.cancel();
	}

private:
	void process_received_data(std::string& data,
		unsigned long message_id) {
		// skip magic number
		get_ul_prefix(data);

		// skip message id
		get_ul_prefix(data);

		// skip embedded length
		get_ul_prefix(data);

		liblec::auto_mutex lock(p_this_client_->d_.data_lock_);
		p_this_client_->d_.data_[message_id].data = data;
		p_this_client_->d_.data_[message_id].received = true;
	}

	void check_deadline() {
		if (stopped_)
			return;

		/*
		** Check whether the deadline has passed. We compare the deadline against
		** the current time since a new asynchronous operation may have moved the
		** deadline before this actor had a chance to run.
		*/
		if (deadline_.expires_at() <= boost::asio::deadline_timer::traits_type::now()) {
			/*
			** The deadline has passed. Close socket.
			*/
			socket_.shutdown(plain_socket::shutdown_both);
			socket_.close();

			/*
			** There is no longer an active deadline. The expiry is set to positive
			** infinity so that the actor takes no action until a new deadline is set.
			*/
			deadline_.expires_at(boost::posix_time::pos_infin);
		}

		// Put the actor back to sleep.
		deadline_.async_wait(boost::bind(&client_async::check_deadline, this));
	}

	enum { buffer_size = 1024 * 64 };
	char buffer_[buffer_size];

	liblec::lecnet::tcp::client* p_this_client_ = nullptr;

	boost::asio::deadline_timer deadline_;
	std::string received_;
	plain_socket socket_;
	bool stopped_;
};

liblec::lecnet::tcp::client::client() :
	d_(*new impl) {
	d_.address_ = "127.0.0.1";
	d_.port_ = 2000;
	d_.use_ssl_ = true;
	d_.p_socket_ = nullptr;

	d_.data_.clear();
	d_.result_.connected = false;
	d_.result_.error.clear();
}

liblec::lecnet::tcp::client::~client() {
	disconnect();

	// ensure the async operation is completed before deleting
	if (d_.fut_.valid())
		d_.fut_.get();

	delete& d_;
}

void liblec::lecnet::tcp::client::impl::client_func(
	liblec::lecnet::tcp::client* p_current) {
	try {
		std::string sHost = p_current->d_.address_;
		std::string sPort = std::to_string(p_current->d_.port_);

		try {
			// Create io service
			p_current->d_.p_io_service_ = new boost::asio::io_service;

			boost::asio::ip::tcp::resolver resolver(*p_current->d_.p_io_service_);
			boost::asio::ip::tcp::resolver::query query(sHost, sPort);
			tcp_iterator iterator = resolver.resolve(query);

			if (p_current->d_.use_ssl_) {
				boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
				ctx.load_verify_file(p_current->d_.ca_cert_path_);

				liblec::lecnet::tcp::client::client_async_ssl c(p_current,
					p_current->d_.p_io_service_, ctx, iterator);

				p_current->d_.p_io_service_->run();
			}
			else {
				liblec::lecnet::tcp::client::client_async c(p_current,
					p_current->d_.p_io_service_, iterator);

				p_current->d_.p_io_service_->run();
			}
		}
		catch (std::exception& e) {
			auto_mutex lock(p_current->d_.error_lock_);
			p_current->d_.error_ = "Exception: " + std::string(e.what());
		}

		// client thread exiting
	}
	catch (std::exception& e) {
		auto_mutex lock(p_current->d_.error_lock_);
		p_current->d_.error_ = "Exception: " + std::string(e.what());
	}

	// it's essential to limit the scope of this mutex
	{
		liblec::auto_mutex lock(p_current->d_.result_lock_);
		p_current->d_.result_.connected = false;
		p_current->d_.result_.error = p_current->d_.error_;
	}

	// it's essential to limit the scope of this mutex
	{
		liblec::auto_mutex lock(p_current->d_.connecting_lock_);
		p_current->d_.connecting_ = false;
	}

	// delete io service
	if (p_current->d_.p_io_service_) {
		delete p_current->d_.p_io_service_;
		p_current->d_.p_io_service_ = nullptr;
	}
}

bool liblec::lecnet::tcp::client::connect(const client_params& params,
	std::string& error) {
	if (running()) {
		// allow only one thread
		return true;
	}

	d_.timeout_seconds_ = params.timeout_seconds;
	d_.address_ = params.address;
	d_.port_ = params.port;
	d_.use_ssl_ = params.use_ssl;
	d_.ca_cert_path_ = params.ca_cert_path;
	d_.magic_number_ = params.magic_number;

	try {
		// run client task asynchronously
		d_.fut_ = std::async(std::launch::async,
			d_.client_func, this);

		liblec::auto_mutex lock(d_.connecting_lock_);
		d_.connecting_ = true;
	}
	catch (std::exception& e) {
		error = e.what();
		return false;
	}

	return true;
}

bool liblec::lecnet::tcp::client::connecting() {
	liblec::auto_mutex lock(d_.connecting_lock_);
	return d_.connecting_;
}

bool liblec::lecnet::tcp::client::connected(std::string& error) {
	error.clear();

	liblec::auto_mutex lock(d_.result_lock_);

	if (!d_.result_.connected)
		error = d_.result_.error;

	return d_.result_.connected;
}

bool liblec::lecnet::tcp::client::running() {
	if (d_.fut_.valid())
		return d_.fut_.wait_for(std::chrono::seconds{ 0 }) != std::future_status::ready;
	else
		return false;
}

void liblec::lecnet::tcp::client::impl::do_send_data(const std::string& raw_to_send,
	unsigned long id) {
	std::string to_send;

	if (!raw_to_send.empty()) {
		to_send = raw_to_send;

		unsigned long length = static_cast<unsigned long>
			(to_send.length() * sizeof(char))	// space for the actual message
			+ sizeof(unsigned long)				// space for data length
			+ sizeof(unsigned long)				// space for message ID
			+ sizeof(unsigned long);			// space magic number

		// prefix data with it's length
		prefix_with_ul(length, to_send);

		// prefix with message ID
		prefix_with_ul(id, to_send);

		// prefix with magic number
		prefix_with_ul(magic_number_, to_send);

		// send data to server
		if (p_socket_) {
			size_t bytes_transferred = 0;

			if (use_ssl_) {
				bytes_transferred = boost::asio::write(*((ssl_socket*)p_socket_),
					boost::asio::buffer(to_send.c_str(), to_send.length()));
			}
			else {
				bytes_transferred = boost::asio::write(*((plain_socket*)p_socket_),
					boost::asio::buffer(to_send.c_str(), to_send.length()));
			}

			liblec::auto_mutex lock(traffic_lock_);
			traffic_.out += bytes_transferred;
		}
	}
}

bool liblec::lecnet::tcp::client::send_data(const std::string& data,
	std::string& received,
	const long& timeout_seconds,
	std::function<bool()> busy_function,
	std::string& error) {
	unsigned long message_id = 0;
	boost::asio::deadline_timer* p_deadline = nullptr;

	if (!running()) {
		error = "Not connected to server";
		return false;
	}

	try {
		if (d_.p_io_service_)
			p_deadline = new boost::asio::deadline_timer(*d_.p_io_service_);

		// Set a deadline for the send/receive operation.
		long time_out = 10;	// default to 10 seconds

		if (timeout_seconds > 0)
			time_out = timeout_seconds;

		if (p_deadline)
			p_deadline->expires_from_now(boost::posix_time::seconds(time_out));

		received.clear();

		if (d_.p_socket_) {
			if (d_.message_id_ < max_prefix_size())
				d_.message_id_++;
			else
				d_.message_id_ = 1;

			message_id = d_.message_id_;

			{
				auto_mutex lock(d_.data_lock_);
				received_data data;
				d_.data_.insert(
					std::pair<unsigned long, received_data>(message_id, data));
			}

			d_.do_send_data(data, message_id);

			// wait until data has been sent, and response is received from server
			while (running()) {
				{
					auto_mutex lock(d_.data_lock_);
					if (d_.data_[message_id].received)
						break;
				}

				if (busy_function)
					busy_function();

				if (p_deadline) {
					if (p_deadline->expires_at() <=
						boost::asio::deadline_timer::traits_type::now()) {
						// timeout_seconds has passed
						auto_mutex lock(d_.data_lock_);
						d_.data_[message_id].error = "Send/Receive timeout";
						p_deadline->cancel();
						break;
					}
				}
			}
		}
	}
	catch (std::exception& e) {
		auto_mutex lock(d_.data_lock_);
		d_.data_[message_id].error = "Exception: " + std::string(e.what());
	}

	if (p_deadline) {
		try {
			p_deadline->cancel();
			delete p_deadline;
			p_deadline = nullptr;
		}
		catch (std::exception& e) {
			auto_mutex lock(d_.data_lock_);
			d_.data_[message_id].error = "Exception: " + std::string(e.what());
		}
	}

	auto_mutex lock(d_.data_lock_);

	if (d_.data_[message_id].data.empty()) {
		if (d_.data_[message_id].error.empty()) {
			auto_mutex lock(d_.error_lock_);
			if (!d_.error_.empty()) {
				error = d_.error_;
				d_.error_.clear();
			}
			else
				error = "Not connected to server";	// what else could have happened?
		}
		else {
			error = d_.data_[message_id].error;
			d_.data_[message_id].error.clear();
		}

		d_.data_.erase(message_id);
		return false;
	}

	received = d_.data_[message_id].data;
	d_.data_.erase(message_id);

	return true;
}

void liblec::lecnet::tcp::client::impl::send_func(unsigned long data_id,
	client* p_current) {
	try {
		bool result = true;
		std::string received;
		std::string error;

		// send data (blocking call)
		result = p_current->send_data(p_current->d_.send_queue_.at(data_id).data, received,
			p_current->d_.send_queue_.at(data_id).timeout_seconds, nullptr, error);

		liblec::auto_mutex lock(p_current->d_.send_queue_lock_);

		p_current->d_.send_queue_.at(data_id).result = result;
		p_current->d_.send_queue_.at(data_id).received = received;
		p_current->d_.send_queue_.at(data_id).error = error;
	}
	catch (std::exception& e) {
		liblec::auto_mutex lock(p_current->d_.send_queue_lock_);

		p_current->d_.send_queue_.at(data_id).result = false;
		p_current->d_.send_queue_.at(data_id).received.clear();
		p_current->d_.send_queue_.at(data_id).error = e.what();
	}
}

bool liblec::lecnet::tcp::client::send_data_async(const std::string& data,
	const long& timeout_seconds,
	unsigned long& data_id,
	std::string& error) {
	if (d_.data_id_ < max_prefix_size())
		d_.data_id_++;
	else
		d_.data_id_ = 1;

	data_id = d_.data_id_;

	liblec::auto_mutex lock(d_.send_queue_lock_);

	d_.send_queue_[data_id].data_id = data_id;
	d_.send_queue_[data_id].data = data;
	d_.send_queue_[data_id].timeout_seconds = timeout_seconds;

	try {
		// run send task asynchronously
		d_.send_queue_[data_id].fut = std::async(std::launch::async,
			d_.send_func, data_id, this);
	}
	catch (std::exception& e) {
		error = e.what();
		return false;
	}

	return true;
}

bool liblec::lecnet::tcp::client::sending(const unsigned long& data_id) {
	liblec::auto_mutex lock(d_.send_queue_lock_);

	try {
		if (d_.send_queue_.at(data_id).fut.valid())
			return d_.send_queue_.at(data_id).fut.wait_for(std::chrono::seconds{ 0 }) !=
			std::future_status::ready;
		else
			return false;
	}
	catch (std::exception&) {
		// probably already deleted from map
		return false;
	}
}

bool liblec::lecnet::tcp::client::get_response(const unsigned long& data_id,
	std::string& received,
	std::string& error) {
	received.clear();

	liblec::auto_mutex lock(d_.send_queue_lock_);

	try {
		bool result = d_.send_queue_.at(data_id).result;
		error = d_.send_queue_.at(data_id).error;
		received = d_.send_queue_.at(data_id).received;

		// remove from queue
		d_.send_queue_.erase(data_id);

		return result;
	}
	catch (std::exception& e) {
		received.clear();
		error = e.what();
		return false;
	}
}

void liblec::lecnet::tcp::client::disconnect() {
	if (running() && d_.p_io_service_) {
		if (d_.p_socket_) {
			try {
				if (d_.use_ssl_)
					((ssl_socket*)d_.p_socket_)->lowest_layer().shutdown(
						plain_socket::shutdown_both);
				else
					((plain_socket*)d_.p_socket_)->shutdown(plain_socket::shutdown_both);
			}
			catch (std::exception&) {
				// ignore error
			}
		}
	}

	// wait for the actual disconnection to be registered before exiting
	std::string error;
	while (connected(error))
		boost::this_thread::sleep(boost::posix_time::milliseconds(1));
}

void liblec::lecnet::tcp::client::traffic(liblec::lecnet::network_traffic& traffic) {
	liblec::auto_mutex lock(d_.traffic_lock_);
	traffic = d_.traffic_;
}
