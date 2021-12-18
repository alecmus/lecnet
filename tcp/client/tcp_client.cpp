//
// tcp_client.cpp - tcp/ip client implementation
//
// lecnet network library, part of the liblec library
// Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
//
// Released under the MIT license. For full details see the
// file LICENSE.txt
//

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

	std::future<void> _fut;
	boost::asio::io_service* _p_io_service = nullptr;
	void* _p_socket = nullptr;

	long _timeout_seconds;
	std::string _address;
	unsigned short _port;
	bool _use_ssl;
	std::string _ca_cert_path;

	// in-class message ID tracker to ensure each message is sent with a unique ID
	unsigned long _message_id = 0;
	unsigned long _data_id = 0;

	std::string _error;
	liblec::mutex _error_lock;

	connect_result _result;
	liblec::mutex _result_lock;

	// Map for data received from the server. Key is the message ID and value is the data.
	std::map<unsigned long, received_data> _data;
	liblec::mutex _data_lock;

	std::map<unsigned long, send_info> _send_queue;
	liblec::mutex _send_queue_lock;

	liblec::lecnet::network_traffic _traffic;
	liblec::mutex _traffic_lock;

	bool _connecting = false;
	liblec::mutex _connecting_lock;

	unsigned long _magic_number = 0;

	friend client;
};

class liblec::lecnet::tcp::client::client_async_ssl {
public:
	client_async_ssl(liblec::lecnet::tcp::client* p_this_client,
		boost::asio::io_service* pio_service,
		boost::asio::ssl::context& context,
		tcp_iterator endpoint_iterator)
		: _socket(*pio_service, context),
		_p_this_client(p_this_client),
		_deadline(*pio_service),
		_stopped(false) {

		_socket.set_verify_mode(boost::asio::ssl::verify_peer);
		_socket.set_verify_callback(
			boost::bind(&client_async_ssl::verify_certificate, this, _1, _2));

		boost::asio::async_connect(_socket.lowest_layer(), endpoint_iterator,
			boost::bind(&client_async_ssl::handle_connect, this,
				boost::asio::placeholders::error));

		/*
		** Start the deadline actor. You will note that we're not setting any
		** particular deadline here. Instead, the connect and input actors will
		** update the deadline prior to each asynchronous operation or as desired.
		*/
		_deadline.async_wait(boost::bind(&client_async_ssl::check_deadline, this));
	}

	~client_async_ssl() {
		try {
			if (socket().is_open())
				socket().close();

			_p_this_client->_d._p_socket = nullptr;
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
			long time_out = _p_this_client->_d._timeout_seconds;

			if (time_out > 0) {
				// Set a deadline for the connect operation.
				_deadline.expires_from_now(
					boost::posix_time::seconds(_p_this_client->_d._timeout_seconds));
			}

			_socket.async_handshake(boost::asio::ssl::stream_base::client,
				boost::bind(&client_async_ssl::handle_handshake, this,
					boost::asio::placeholders::error));
		}
		else {
			{
				liblec::auto_mutex lock(_p_this_client->_d._error_lock);
				_p_this_client->_d._error = "Connect failed: " + error.message();
			}

			_stopped = true;
			_deadline.cancel();
		}
	}

	void handle_handshake(const boost::system::error_code& error) {
		if (!error) {
			// connected successfully

			// There is no longer an active deadline. The expiry is set to positive
			// infinity so that the actor takes no action until a new deadline is set.
			_deadline.expires_at(boost::posix_time::pos_infin);

			_p_this_client->_d._p_socket = &_socket;

			// it's essential to limit the scope of this mutex
			{
				liblec::auto_mutex lock(_p_this_client->_d._result_lock);
				_p_this_client->_d._result.connected = true;
				_p_this_client->_d._result.error.clear();
			}

			// it's essential to limit the scope of this mutex
			{
				liblec::auto_mutex lock(_p_this_client->_d._connecting_lock);
				_p_this_client->_d._connecting = false;
			}

			execute();
		}
		else {
			{
				liblec::auto_mutex lock(_p_this_client->_d._error_lock);
				_p_this_client->_d._error = "Handshake failed: " + error.message();
			}

			_stopped = true;
			_deadline.cancel();
		}
	}

	// execute entry point
	void execute() {
		// read data
		while (true) {
			boost::system::error_code error;
			size_t bytes_transferred = _socket.read_some(boost::asio::buffer(_buffer, buffer_size),
				error);

			{
				liblec::auto_mutex lock(_p_this_client->_d._traffic_lock);
				_p_this_client->_d._traffic.in += bytes_transferred;
			}

			if (!error) {
				_received += std::string(_buffer, bytes_transferred);

				// retrieve magic number
				if (get_ul_prefix(_received, 1) == _p_this_client->_d._magic_number) {
					// retrieve embedded length
					unsigned long length = get_ul_prefix(_received, 3);

					if (length == _received.length()) {
						// all data has been received

						// retrieve message ID
						unsigned long message_id = get_ul_prefix(_received, 2);

						// process the data
						process_received_data(_received, message_id);

						// clear
						_received.clear();
					}
					else {
						if (length > _received.length()) {
							// essential to stay connected
						}
						else {
							// invalid data received
							liblec::auto_mutex lock(_p_this_client->_d._error_lock);
							_p_this_client->_d._error = "Invalid data received";
							break;
						}
					}
				}
				else {
					// invalid data received
					liblec::auto_mutex lock(_p_this_client->_d._error_lock);
					_p_this_client->_d._error = "Invalid data received";
					break;
				}
			}
			else {
				// client disconnected
				liblec::auto_mutex lock(_p_this_client->_d._error_lock);
				_p_this_client->_d._error = "Client disconnected from server: " + error.message();
				break;
			}
		}

		_stopped = true;
		_deadline.cancel();
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

		liblec::auto_mutex lock(_p_this_client->_d._data_lock);

		try {
			if (_p_this_client->_d._data.find(message_id) !=
				_p_this_client->_d._data.end()) {
				_p_this_client->_d._data.at(message_id).data = data;
				_p_this_client->_d._data.at(message_id).received = true;
			}
		}
		catch (std::exception& e) {
			// probably already deleted from map
			liblec::auto_mutex lock(_p_this_client->_d._error_lock);
			_p_this_client->_d._error = "Exception: " + std::string(e.what());
		}
	}

	void check_deadline() {
		if (_stopped)
			return;

		/*
		** Check whether the deadline has passed. We compare the deadline against
		** the current time since a new asynchronous operation may have moved the
		** deadline before this actor had a chance to run.
		*/
		if (_deadline.expires_at() <= boost::asio::deadline_timer::traits_type::now()) {
			/*
			** The deadline has passed. Close socket.
			*/
			socket().shutdown(plain_socket::shutdown_both);
			socket().close();

			/*
			** There is no longer an active deadline. The expiry is set to positive
			** infinity so that the actor takes no action until a new deadline is set.
			*/
			_deadline.expires_at(boost::posix_time::pos_infin);
		}

		// Put the actor back to sleep.
		_deadline.async_wait(boost::bind(&client_async_ssl::check_deadline, this));
	} // check_deadline

	ssl_socket::lowest_layer_type& socket() {
		return _socket.lowest_layer();
	}

	enum { buffer_size = 1024 * 64 };
	char _buffer[buffer_size];

	liblec::lecnet::tcp::client* _p_this_client = nullptr;

	boost::asio::deadline_timer _deadline;
	std::string _received;
	ssl_socket _socket;
	bool _stopped;
};

class liblec::lecnet::tcp::client::client_async {
public:
	client_async(liblec::lecnet::tcp::client* p_this_client,
		boost::asio::io_service* pio_service,
		tcp_iterator endpoint_iterator)
		: _socket(*pio_service),
		_p_this_client(p_this_client),
		_deadline(*pio_service),
		_stopped(false) {

		boost::asio::async_connect(_socket, endpoint_iterator,
			boost::bind(&client_async::handle_connect, this,
				boost::asio::placeholders::error));

		/*
		** Start the deadline actor. You will note that we're not setting any
		** particular deadline here. Instead, the connect and input actors will
		** update the deadline prior to each asynchronous operation or as desired.
		*/
		_deadline.async_wait(boost::bind(&client_async::check_deadline, this));

		long time_out = _p_this_client->_d._timeout_seconds;

		if (time_out > 0) {
			// Set a deadline for the connect operation.
			_deadline.expires_from_now(
				boost::posix_time::seconds(_p_this_client->_d._timeout_seconds));
		}
	}

	~client_async() {
		try {
			if (_socket.is_open())
				_socket.close();

			_p_this_client->_d._p_socket = nullptr;
		}
		catch (const std::exception&) {}
	}

	void handle_connect(const boost::system::error_code& error) {
		if (!error) {
			// connected successfully
			// There is no longer an active deadline. The expiry is set to positive
			// infinity so that the actor takes no action until a new deadline is set.
			_deadline.expires_at(boost::posix_time::pos_infin);

			_p_this_client->_d._p_socket = &_socket;

			// it's essential to limit the scope of this mutex
			{
				liblec::auto_mutex lock(_p_this_client->_d._result_lock);
				_p_this_client->_d._result.connected = true;
				_p_this_client->_d._result.error.clear();
			}

			// it's essential to limit the scope of this mutex
			{
				liblec::auto_mutex lock(_p_this_client->_d._connecting_lock);
				_p_this_client->_d._connecting = false;
			}

			execute();
		}
		else {
			{
				liblec::auto_mutex lock(_p_this_client->_d._error_lock);
				_p_this_client->_d._error = "Connect failed: " + error.message();
			}

			_stopped = true;
			_deadline.cancel();
		}
	}

	// execute entry point
	void execute() {
		// read data
		while (true) {
			boost::system::error_code error;
			size_t bytes_transferred = _socket.read_some(boost::asio::buffer(_buffer, buffer_size),
				error);

			{
				liblec::auto_mutex lock(_p_this_client->_d._traffic_lock);
				_p_this_client->_d._traffic.in += bytes_transferred;
			}

			if (!error) {
				_received += std::string(_buffer, bytes_transferred);

				// retrieve magic number
				if (get_ul_prefix(_received, 1) == _p_this_client->_d._magic_number) {
					// retrieve embedded length
					unsigned long length = get_ul_prefix(_received, 3);

					if (length == _received.length()) {
						// all data has been received

						// retrieve message ID
						unsigned long message_id = get_ul_prefix(_received, 2);

						// process the data
						process_received_data(_received, message_id);

						// clear
						_received.clear();
					}
					else {
						if (length > _received.length()) {
							// essential to stay connected
						}
						else {
							// invalid data received
							liblec::auto_mutex lock(_p_this_client->_d._error_lock);
							_p_this_client->_d._error = "Invalid data received";
							break;
						}
					}
				}
				else {
					// invalid data received
					liblec::auto_mutex lock(_p_this_client->_d._error_lock);
					_p_this_client->_d._error = "Invalid data received";
					break;
				}
			}
			else {
				// client disconnected
				liblec::auto_mutex lock(_p_this_client->_d._error_lock);
				_p_this_client->_d._error = "Client disconnected from server: " + error.message();
				break;
			}
		}

		_stopped = true;
		_deadline.cancel();
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

		liblec::auto_mutex lock(_p_this_client->_d._data_lock);
		_p_this_client->_d._data[message_id].data = data;
		_p_this_client->_d._data[message_id].received = true;
	}

	void check_deadline() {
		if (_stopped)
			return;

		/*
		** Check whether the deadline has passed. We compare the deadline against
		** the current time since a new asynchronous operation may have moved the
		** deadline before this actor had a chance to run.
		*/
		if (_deadline.expires_at() <= boost::asio::deadline_timer::traits_type::now()) {
			/*
			** The deadline has passed. Close socket.
			*/
			_socket.shutdown(plain_socket::shutdown_both);
			_socket.close();

			/*
			** There is no longer an active deadline. The expiry is set to positive
			** infinity so that the actor takes no action until a new deadline is set.
			*/
			_deadline.expires_at(boost::posix_time::pos_infin);
		}

		// Put the actor back to sleep.
		_deadline.async_wait(boost::bind(&client_async::check_deadline, this));
	}

	enum { buffer_size = 1024 * 64 };
	char _buffer[buffer_size];

	liblec::lecnet::tcp::client* _p_this_client = nullptr;

	boost::asio::deadline_timer _deadline;
	std::string _received;
	plain_socket _socket;
	bool _stopped;
};

liblec::lecnet::tcp::client::client() :
	_d(*new impl) {
	_d._address = "127.0.0.1";
	_d._port = 2000;
	_d._use_ssl = true;
	_d._p_socket = nullptr;

	_d._data.clear();
	_d._result.connected = false;
	_d._result.error.clear();
}

liblec::lecnet::tcp::client::~client() {
	disconnect();

	// ensure the async operation is completed before deleting
	if (_d._fut.valid())
		_d._fut.get();

	delete& _d;
}

void liblec::lecnet::tcp::client::impl::client_func(
	liblec::lecnet::tcp::client* p_current) {
	try {
		std::string sHost = p_current->_d._address;
		std::string sPort = std::to_string(p_current->_d._port);

		try {
			// Create io service
			p_current->_d._p_io_service = new boost::asio::io_service;

			boost::asio::ip::tcp::resolver resolver(*p_current->_d._p_io_service);
			boost::asio::ip::tcp::resolver::query query(sHost, sPort);
			tcp_iterator iterator = resolver.resolve(query);

			if (p_current->_d._use_ssl) {
				boost::asio::ssl::context ctx(boost::asio::ssl::context::sslv23);
				ctx.load_verify_file(p_current->_d._ca_cert_path);

				liblec::lecnet::tcp::client::client_async_ssl c(p_current,
					p_current->_d._p_io_service, ctx, iterator);

				p_current->_d._p_io_service->run();
			}
			else {
				liblec::lecnet::tcp::client::client_async c(p_current,
					p_current->_d._p_io_service, iterator);

				p_current->_d._p_io_service->run();
			}
		}
		catch (std::exception& e) {
			auto_mutex lock(p_current->_d._error_lock);
			p_current->_d._error = "Exception: " + std::string(e.what());
		}

		// client thread exiting
	}
	catch (std::exception& e) {
		auto_mutex lock(p_current->_d._error_lock);
		p_current->_d._error = "Exception: " + std::string(e.what());
	}

	// it's essential to limit the scope of this mutex
	{
		liblec::auto_mutex lock(p_current->_d._result_lock);
		p_current->_d._result.connected = false;
		p_current->_d._result.error = p_current->_d._error;
	}

	// it's essential to limit the scope of this mutex
	{
		liblec::auto_mutex lock(p_current->_d._connecting_lock);
		p_current->_d._connecting = false;
	}

	// delete io service
	if (p_current->_d._p_io_service) {
		delete p_current->_d._p_io_service;
		p_current->_d._p_io_service = nullptr;
	}
}

bool liblec::lecnet::tcp::client::connect(const client_params& params,
	std::string& error) {
	if (running()) {
		// allow only one thread
		return true;
	}

	_d._timeout_seconds = params.timeout_seconds;
	_d._address = params.address;
	_d._port = params.port;
	_d._use_ssl = params.use_ssl;
	_d._ca_cert_path = params.ca_cert_path;
	_d._magic_number = params.magic_number;

	try {
		// run client task asynchronously
		_d._fut = std::async(std::launch::async,
			_d.client_func, this);

		liblec::auto_mutex lock(_d._connecting_lock);
		_d._connecting = true;
	}
	catch (std::exception& e) {
		error = e.what();
		return false;
	}

	return true;
}

bool liblec::lecnet::tcp::client::connecting() {
	liblec::auto_mutex lock(_d._connecting_lock);
	return _d._connecting;
}

bool liblec::lecnet::tcp::client::connected(std::string& error) {
	error.clear();

	liblec::auto_mutex lock(_d._result_lock);

	if (!_d._result.connected)
		error = _d._result.error;

	return _d._result.connected;
}

bool liblec::lecnet::tcp::client::running() {
	if (_d._fut.valid())
		return _d._fut.wait_for(std::chrono::seconds{ 0 }) != std::future_status::ready;
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
		prefix_with_ul(_magic_number, to_send);

		// send data to server
		if (_p_socket) {
			size_t bytes_transferred = 0;

			if (_use_ssl) {
				bytes_transferred = boost::asio::write(*((ssl_socket*)_p_socket),
					boost::asio::buffer(to_send.c_str(), to_send.length()));
			}
			else {
				bytes_transferred = boost::asio::write(*((plain_socket*)_p_socket),
					boost::asio::buffer(to_send.c_str(), to_send.length()));
			}

			liblec::auto_mutex lock(_traffic_lock);
			_traffic.out += bytes_transferred;
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
		if (_d._p_io_service)
			p_deadline = new boost::asio::deadline_timer(*_d._p_io_service);

		// Set a deadline for the send/receive operation.
		long time_out = 10;	// default to 10 seconds

		if (timeout_seconds > 0)
			time_out = timeout_seconds;

		if (p_deadline)
			p_deadline->expires_from_now(boost::posix_time::seconds(time_out));

		received.clear();

		if (_d._p_socket) {
			if (_d._message_id < max_prefix_size())
				_d._message_id++;
			else
				_d._message_id = 1;

			message_id = _d._message_id;

			{
				auto_mutex lock(_d._data_lock);
				received_data data;
				_d._data.insert(
					std::pair<unsigned long, received_data>(message_id, data));
			}

			_d.do_send_data(data, message_id);

			// wait until data has been sent, and response is received from server
			while (running()) {
				{
					auto_mutex lock(_d._data_lock);
					if (_d._data[message_id].received)
						break;
				}

				if (busy_function)
					busy_function();

				if (p_deadline) {
					if (p_deadline->expires_at() <=
						boost::asio::deadline_timer::traits_type::now()) {
						// timeout_seconds has passed
						auto_mutex lock(_d._data_lock);
						_d._data[message_id].error = "Send/Receive timeout";
						p_deadline->cancel();
						break;
					}
				}
			}
		}
	}
	catch (std::exception& e) {
		auto_mutex lock(_d._data_lock);
		_d._data[message_id].error = "Exception: " + std::string(e.what());
	}

	if (p_deadline) {
		try {
			p_deadline->cancel();
			delete p_deadline;
			p_deadline = nullptr;
		}
		catch (std::exception& e) {
			auto_mutex lock(_d._data_lock);
			_d._data[message_id].error = "Exception: " + std::string(e.what());
		}
	}

	auto_mutex lock(_d._data_lock);

	if (_d._data[message_id].data.empty()) {
		if (_d._data[message_id].error.empty()) {
			auto_mutex lock(_d._error_lock);
			if (!_d._error.empty()) {
				error = _d._error;
				_d._error.clear();
			}
			else
				error = "Not connected to server";	// what else could have happened?
		}
		else {
			error = _d._data[message_id].error;
			_d._data[message_id].error.clear();
		}

		_d._data.erase(message_id);
		return false;
	}

	received = _d._data[message_id].data;
	_d._data.erase(message_id);

	return true;
}

void liblec::lecnet::tcp::client::impl::send_func(unsigned long data_id,
	client* p_current) {
	try {
		bool result = true;
		std::string received;
		std::string error;

		// send data (blocking call)
		result = p_current->send_data(p_current->_d._send_queue.at(data_id).data, received,
			p_current->_d._send_queue.at(data_id).timeout_seconds, nullptr, error);

		liblec::auto_mutex lock(p_current->_d._send_queue_lock);

		p_current->_d._send_queue.at(data_id).result = result;
		p_current->_d._send_queue.at(data_id).received = received;
		p_current->_d._send_queue.at(data_id).error = error;
	}
	catch (std::exception& e) {
		liblec::auto_mutex lock(p_current->_d._send_queue_lock);

		p_current->_d._send_queue.at(data_id).result = false;
		p_current->_d._send_queue.at(data_id).received.clear();
		p_current->_d._send_queue.at(data_id).error = e.what();
	}
}

bool liblec::lecnet::tcp::client::send_data_async(const std::string& data,
	const long& timeout_seconds,
	unsigned long& data_id,
	std::string& error) {
	if (_d._data_id < max_prefix_size())
		_d._data_id++;
	else
		_d._data_id = 1;

	data_id = _d._data_id;

	liblec::auto_mutex lock(_d._send_queue_lock);

	_d._send_queue[data_id].data_id = data_id;
	_d._send_queue[data_id].data = data;
	_d._send_queue[data_id].timeout_seconds = timeout_seconds;

	try {
		// run send task asynchronously
		_d._send_queue[data_id].fut = std::async(std::launch::async,
			_d.send_func, data_id, this);
	}
	catch (std::exception& e) {
		error = e.what();
		return false;
	}

	return true;
}

bool liblec::lecnet::tcp::client::sending(const unsigned long& data_id) {
	liblec::auto_mutex lock(_d._send_queue_lock);

	try {
		if (_d._send_queue.at(data_id).fut.valid())
			return _d._send_queue.at(data_id).fut.wait_for(std::chrono::seconds{ 0 }) !=
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

	liblec::auto_mutex lock(_d._send_queue_lock);

	try {
		bool result = _d._send_queue.at(data_id).result;
		error = _d._send_queue.at(data_id).error;
		received = _d._send_queue.at(data_id).received;

		// remove from queue
		_d._send_queue.erase(data_id);

		return result;
	}
	catch (std::exception& e) {
		received.clear();
		error = e.what();
		return false;
	}
}

void liblec::lecnet::tcp::client::disconnect() {
	if (running() && _d._p_io_service) {
		if (_d._p_socket) {
			try {
				if (_d._use_ssl)
					((ssl_socket*)_d._p_socket)->lowest_layer().shutdown(
						plain_socket::shutdown_both);
				else
					((plain_socket*)_d._p_socket)->shutdown(plain_socket::shutdown_both);
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
	liblec::auto_mutex lock(_d._traffic_lock);
	traffic = _d._traffic;
}
