//
// tcp_server_async_ssl.cpp - tcp/ip asynchronous server (with SSL encryption) implementation
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

#include "../../tcp.h"
#include "../../helper_fxns/helper_fxns.h"
#include "../../auto_mutex/auto_mutex.h"
#include "server_log.h"

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

typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket;

class liblec::lecnet::tcp::server_async_ssl::impl {
public:
	size_t get_number_of_clients();
	unsigned short get_max_clients();
	void log(const std::string& event);

	static void server_func(liblec::lecnet::tcp::server_async_ssl* p_current);

	std::string _host_address;
	unsigned short _port;
	unsigned short _max_clients;
	network_traffic _total_traffic;

	struct client_info_internal {
		liblec::lecnet::tcp::server::client_info client_info;
		void* p_socket_internal = nullptr;
	};

	std::map<client_address, client_info_internal> _clients;

	std::future<void> _fut;
	boost::asio::io_service* _p_io_service = nullptr;

	std::string _server_cert;
	std::string _server_cert_key;
	std::string _server_cert_key_password;

	// critical section lockers
	static liblec::mutex _server_lock;
	static liblec::mutex _clients_lock;
	static liblec::mutex _log_lock;

	friend class _session_async_ssl;
	friend class _server_async_ssl;
	liblec::lecnet::tcp::server_async_ssl* p_tcp_server_ssl;
	bool _starting = false;
	liblec::mutex _starting_lock;
	unsigned long _magic_number = 0;
};

void liblec::lecnet::tcp::server_async_ssl::impl::log(const std::string& event) {
	liblec::auto_mutex lock(_log_lock);
	p_tcp_server_ssl->log(time_stamp(), event);
}

unsigned short liblec::lecnet::tcp::server_async_ssl::impl::get_max_clients() {
	return _max_clients;
}

size_t liblec::lecnet::tcp::server_async_ssl::impl::get_number_of_clients() {
	liblec::auto_mutex lock(_clients_lock);
	return _clients.size();
}

class liblec::lecnet::tcp::server_async_ssl::_session_async_ssl {
public:
	_session_async_ssl(boost::asio::io_service& io_service,
		boost::asio::ssl::context& context,
		liblec::lecnet::tcp::server_async_ssl* p_this)
		: _socket(io_service, context),
		_denied(false),
		_p_this(p_this) {}

	~_session_async_ssl() {
		// remove this client to the clients map
		liblec::auto_mutex lock(impl::_clients_lock);
		_p_this->_d._clients.erase(_address);

		// client has disconnected
		if (!_denied)
			_p_this->_d.log(server_log::client_disconnected(std::string(_address), _last_error));
	}

	ssl_socket::lowest_layer_type& socket() {
		return _socket.lowest_layer();
	}

	void start(bool deny) {
		_denied = deny;

		if (deny)
			socket().shutdown(boost::asio::ip::tcp::socket::shutdown_both);
		else {
			{
				liblec::auto_mutex lock(impl::_clients_lock);
				impl::client_info_internal this_client;
				this_client.client_info.address =
					socket().remote_endpoint().address().to_string() + ":" +
					std::to_string(socket().remote_endpoint().port());
				_address = this_client.client_info.address;
				this_client.client_info.traffic.in = 0;
				this_client.client_info.traffic.out = 0;
				this_client.p_socket_internal = (void*)& socket();

				// add this client to the clients map
				_p_this->_d._clients[this_client.client_info.address] = this_client;
			}

			_socket.async_handshake(boost::asio::ssl::stream_base::server,
				boost::bind(&_session_async_ssl::handle_handshake, this,
					boost::asio::placeholders::error));
		}
	}

	void handle_handshake(const boost::system::error_code& error) {
		if (!error) {
			{
				liblec::auto_mutex lock(impl::_clients_lock);
				_p_this->_d.log(server_log::client_connected(std::string(_address)));
			}

			do_read();
		}
		else {
			_last_error = error.message();
			delete this;
		}
	}

	void do_read() {
		_socket.async_read_some(boost::asio::buffer(_buffer, buffer_size),
			boost::bind(&_session_async_ssl::handle_read, this,
				boost::asio::placeholders::error,
				boost::asio::placeholders::bytes_transferred));
	}

	void do_write(bool write_all) {
		std::size_t length = 0;

		if (write_all)
			length = _data_to_send.length();

		boost::asio::async_write(_socket,
			boost::asio::buffer(_data_to_send.c_str(), length),
			boost::bind(&_session_async_ssl::handle_write, this,
				boost::asio::placeholders::error));
	}

	void handle_read(const boost::system::error_code& error,
		size_t bytes_transferred) {
		if (!error) {
			_received += std::string(_buffer, bytes_transferred);

			// append data received to client traffic
			append_traffic_in(bytes_transferred);

			// retrieve magic number
			if (get_ul_prefix(_received, 1) == _p_this->_d._magic_number) {
				// retrieve embedded length
				unsigned long length = get_ul_prefix(_received, 3);

				if (length == _received.length()) {
					// all data has been received

					// retrieve message ID
					unsigned long message_id = get_ul_prefix(_received, 2);

					process_received_data(_received, message_id);
					_received.clear();
				}
				else {
					if (length > _received.length())
						do_write(false);	// essential to stay connected
					else {
						_last_error = "Invalid data received";
						do_write(false);	// essential to stay connected
					}
				}
			}
			else {
				_last_error = "Invalid data received";
				do_write(false);	// essential to stay connected
			}
		}
		else {
			_last_error = error.message();
			delete this;
		}
	}

	void handle_write(const boost::system::error_code& error) {
		if (!error)
			do_read();
		else {
			_last_error = error.message();
			delete this;
		}
	}

private:
	void append_traffic_in(size_t iLen) {
		// append data received to client traffic
		liblec::auto_mutex lock(impl::_clients_lock);
		_p_this->_d._clients[_address].client_info.traffic.in += iLen;
		_p_this->_d._total_traffic.in += iLen;
	}

	void append_traffic_out(size_t iLen) {
		// append data received to client traffic
		liblec::auto_mutex lock(impl::_clients_lock);
		_p_this->_d._clients[_address].client_info.traffic.out += iLen;
		_p_this->_d._total_traffic.out += iLen;
	}

	void process_received_data(std::string& data, unsigned long id) {
		// skip magic number
		get_ul_prefix(data);

		// skip message id
		get_ul_prefix(data);

		// skip embedded length
		get_ul_prefix(data);

		/*
		** call the virtual function on_receive(), passing in this client's address and the data
		** received the function will return data to be sent back to the client, if the server so
		** desires
		*/
		_data_to_send = _p_this->on_receive(_address, data);

		if (!_data_to_send.empty()) {
			unsigned long length = static_cast<unsigned long>
				(_data_to_send.length() * sizeof(char))	// space for the actual message
				+ sizeof(unsigned long)					// space for data length
				+ sizeof(unsigned long)					// space for message ID
				+ sizeof(unsigned long);				// space magic number

			// prefix data with it's length
			prefix_with_ul(length, _data_to_send);

			// prefix with message ID
			prefix_with_ul(id, _data_to_send);

			// prefix with magic number
			prefix_with_ul(_p_this->_d._magic_number, _data_to_send);

			// send data to client
			do_write(true);

			// append data sent to client traffic
			append_traffic_out(length);
		}
		else
			do_write(false);	// essential to stay connected
	}

	ssl_socket _socket;

	enum { buffer_size = 1024 * 64 };
	char _buffer[buffer_size];

	liblec::lecnet::tcp::server_async_ssl::client_address _address;
	std::string _received;
	std::string _data_to_send;
	bool _denied;
	std::string _last_error;
	liblec::lecnet::tcp::server_async_ssl* _p_this;
};

class liblec::lecnet::tcp::server_async_ssl::_server_async_ssl {
public:
	_server_async_ssl(boost::asio::ip::address ip,
		short port,
		liblec::lecnet::tcp::server_async_ssl* p_this) :
		_acceptor(*p_this->_d._p_io_service,
			boost::asio::ip::tcp::endpoint(ip, port)),
		_socket(*p_this->_d._p_io_service),
		_context(boost::asio::ssl::context::sslv23),
		_p_this(p_this) {

		_context.set_options(
			boost::asio::ssl::context::default_workarounds
			| boost::asio::ssl::context::no_sslv2
			| boost::asio::ssl::context::single_dh_use);

		if (!_p_this->_d._server_cert_key_password.empty())
			_context.set_password_callback(boost::bind(&_server_async_ssl::get_password, this));

		_context.use_certificate_chain_file(p_this->_d._server_cert);

		std::string server_cert_key = p_this->_d._server_cert_key;

		if (server_cert_key.empty()) {
			// fallback: look for server RSA key in server certificate file
			server_cert_key = p_this->_d._server_cert;
		}

		_context.use_private_key_file(server_cert_key, boost::asio::ssl::context::pem);

		start_accept();

		p_this->_d.log(server_log::start(_acceptor.local_endpoint().address().to_string(),
			_acceptor.local_endpoint().port(),
			"Async SSL"));
		p_this->_d.log(server_log::start_info(std::to_string(p_this->_d.get_max_clients())));

		liblec::auto_mutex lock(_p_this->_d._starting_lock);
		_p_this->_d._starting = false;
	}

	std::string get_password() const {
		return _p_this->_d._server_cert_key_password;
	}

private:
	void start_accept() {
		_session_async_ssl* new_session = new _session_async_ssl(*_p_this->_d._p_io_service,
			_context, _p_this);
		_acceptor.async_accept(new_session->socket(),
			boost::bind(&_server_async_ssl::handle_accept, this, new_session,
				boost::asio::placeholders::error));
	}

	void handle_accept(_session_async_ssl* new_session,
		const boost::system::error_code& error) {
		if (!error) {
			bool deny = false;

			{ // failsafe
				if (_p_this->_d.get_number_of_clients() >= _p_this->_d.get_max_clients())
					deny = true;
			}

			new_session->start(deny);
		}
		else
			delete new_session;

		start_accept();
	}

	boost::asio::ip::tcp::acceptor _acceptor;
	boost::asio::ip::tcp::socket _socket;
	boost::asio::ssl::context _context;
	liblec::lecnet::tcp::server_async_ssl* _p_this;
};

///////////////////////////////////////////////////////////////////////////////////////////////////
liblec::mutex liblec::lecnet::tcp::server_async_ssl::impl::_log_lock;
liblec::mutex liblec::lecnet::tcp::server_async_ssl::impl::_clients_lock;
liblec::mutex liblec::lecnet::tcp::server_async_ssl::impl::_server_lock;

liblec::lecnet::tcp::server_async_ssl::server_async_ssl() :
	_d(*(new impl)) {
	_d.p_tcp_server_ssl = this;
}

liblec::lecnet::tcp::server_async_ssl::~server_async_ssl() {
	// stop server
	stop();

	// ensure the async operation is completed before deleting
	if (_d._fut.valid())
		_d._fut.get();

	delete& _d;
}

void liblec::lecnet::tcp::server_async_ssl::impl::server_func(
	server_async_ssl* p_current) {
	try {
		boost::asio::ip::address ip =
			boost::asio::ip::address::from_string(p_current->_d._host_address);

		_server_async_ssl s(ip, p_current->_d._port, p_current);
		p_current->_d._p_io_service->run();
	}
	catch (std::exception& e) {
		p_current->_d.log(e.what());
	}

	liblec::auto_mutex lock(p_current->_d._starting_lock);
	p_current->_d._starting = false;

	// delete io service
	delete p_current->_d._p_io_service;
	p_current->_d._p_io_service = nullptr;
}

bool liblec::lecnet::tcp::server_async_ssl::start(const server_params& params) {
	if (running()) {
		// allow only one instance
		_d.log(server_log::server_already_running());
		return true;
	}

	_d._host_address = params.ip;
	_d._port = params.port;
	_d._max_clients = params.max_clients;
	_d._server_cert = params.server_cert;
	_d._server_cert_key = params.server_cert_key;
	_d._server_cert_key_password = params.server_cert_key_password;
	_d._magic_number = params.magic_number;

	try {
		// Create io service.
		_d._p_io_service = new boost::asio::io_service;

		// run server task asynchronously
		_d._fut = std::async(std::launch::async,
			_d.server_func, this);

		liblec::auto_mutex lock(_d._starting_lock);
		_d._starting = true;
	}
	catch (std::exception& e) {
		_d.log(e.what());
		return false;
	}

	return true;
}

bool liblec::lecnet::tcp::server_async_ssl::starting() {
	liblec::auto_mutex lock(_d._starting_lock);
	return _d._starting;
}

bool liblec::lecnet::tcp::server_async_ssl::running() {
	if (_d._fut.valid())
		return _d._fut.wait_for(std::chrono::seconds{ 0 }) != std::future_status::ready;
	else
		return false;
}

void liblec::lecnet::tcp::server_async_ssl::close(const client_address& address) {
	liblec::auto_mutex lock(_d._clients_lock);

	try {
		if (!(_d._clients.find(address) == _d._clients.end())) {
			_d.log(server_log::close(std::string(address)));
			boost::asio::ip::tcp::socket* p_socket =
				(boost::asio::ip::tcp::socket*)(_d._clients[address].p_socket_internal);
			p_socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
			p_socket->close();
		}
		else
			_d.log(server_log::close_error(std::string(address)));
	}
	catch (std::exception& e) {
		_d.log(e.what());
	}
} // close

void liblec::lecnet::tcp::server_async_ssl::close() {
	bool log_this = false;

	try {
		liblec::auto_mutex lock(_d._clients_lock);

		if (!_d._clients.empty())
			log_this = true;

		if (log_this)
			_d.log(server_log::close());

		// iterate through map and close client sockets
		for (auto const& it : _d._clients) {
			boost::asio::ip::tcp::socket* p_socket =
				(boost::asio::ip::tcp::socket*)(_d._clients[it.first].p_socket_internal);
			p_socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
			p_socket->close();
		}
	}
	catch (std::exception& e) {
		_d.log(e.what());
		return;
	}

	// wait for all clients to actually get disconnected
	while (true) {
		boost::this_thread::sleep(boost::posix_time::milliseconds(1));

		liblec::auto_mutex lock(_d._clients_lock);
		if (!_d._clients.size())
			break;
	}

	if (log_this)
		_d.log(server_log::closed());
}

bool liblec::lecnet::tcp::server_async_ssl::stop() {
	try {
		close();

		if (running()) {
			// stop the io_service
			_d._p_io_service->stop();

			// wait for server to stop running
			while (running())
				boost::this_thread::sleep(boost::posix_time::milliseconds(1));

			_d.log(server_log::stop());
		}
	}
	catch (std::exception& e) {
		_d.log(e.what());
	}

	return true;
}

void liblec::lecnet::tcp::server_async_ssl::get_client_info(std::vector<client_info>& client_info) {
	liblec::auto_mutex lock(_d._clients_lock);
	client_info.clear();
	client_info.reserve(_d._clients.size());
	for (auto const& it : _d._clients)
		client_info.push_back(it.second.client_info);
}

void liblec::lecnet::tcp::server_async_ssl::traffic(liblec::lecnet::network_traffic& traffic) {
	liblec::auto_mutex lock(_d._clients_lock);
	traffic = _d._total_traffic;
}
