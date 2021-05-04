/*
** tcp_server_async.cpp - tcp/ip asynchronous server implementation
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
	#include <boost/asio.hpp>
	#include <boost/thread.hpp>
	#define _WINSOCKAPI_
#else
	#include <boost/asio.hpp>
	#include <boost/thread.hpp>
#endif

#undef _CRT_SECURE_NO_WARNINGS

class liblec::lecnet::tcp::server_async::impl {
public:
	size_t get_number_of_clients();
	unsigned short get_max_clients();
	void log(const std::string& event);

	static void server_func(liblec::lecnet::tcp::server_async* p_current);

	std::string host_address_;
	unsigned short port_;
	unsigned short max_clients_;
	network_traffic total_traffic_;

	struct client_info_internal {
		liblec::lecnet::tcp::server::client_info client_info;
		void* p_socket_internal = nullptr;
	};

	std::map<client_address, client_info_internal> clients_;

	std::future<void> fut_;
	boost::asio::io_service* p_io_service_ = nullptr;

	// critical section lockers
	static liblec::mutex clients_lock_;
	static liblec::mutex log_locker;

	friend class session_async_;
	friend class server_async_;

	liblec::lecnet::tcp::server_async* p_tcp_server_;

	bool starting_ = false;
	liblec::mutex starting_lock_;

	unsigned long magic_number_ = 0;
};

void liblec::lecnet::tcp::server_async::impl::log(const std::string& event) {
	liblec::auto_mutex lock(log_locker);
	p_tcp_server_->log(time_stamp(), event);
}

unsigned short liblec::lecnet::tcp::server_async::impl::get_max_clients() {
	return max_clients_;
}

size_t liblec::lecnet::tcp::server_async::impl::get_number_of_clients() {
	liblec::auto_mutex lock(clients_lock_);
	return clients_.size();
}

class liblec::lecnet::tcp::server_async::session_async_ :
	public std::enable_shared_from_this<session_async_> {
public:
	session_async_(boost::asio::ip::tcp::socket socket, liblec::lecnet::tcp::server_async* p_this)
		: socket_(std::move(socket)),
		denied_(false),
		p_this_(p_this) {

		liblec::auto_mutex lock(impl::clients_lock_);

		impl::client_info_internal this_client;
		this_client.client_info.address = socket_.remote_endpoint().address().to_string() + ":" +
			std::to_string(socket_.remote_endpoint().port());
		address_ = this_client.client_info.address;
		this_client.client_info.traffic.in = 0;
		this_client.client_info.traffic.out = 0;
		this_client.p_socket_internal = (void*)& socket_;

		// add this client to the clients map
		p_this_->d_.clients_[this_client.client_info.address] = this_client;
	}

	~session_async_() {
		// remove this client to the clients map
		liblec::auto_mutex lock(impl::clients_lock_);
		p_this_->d_.clients_.erase(address_);

		// client has disconnected
		if (!denied_)
			p_this_->d_.log(server_log::client_disconnected(std::string(address_), last_error_));
	}

	void start(bool deny) {
		denied_ = deny;

		if (deny) {
			socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both);
			//p_this_->log(std::string(address_) + " - connection declined");
		}
		else {
			liblec::auto_mutex lock(impl::clients_lock_);
			p_this_->d_.log(server_log::client_connected(std::string(address_)));
		}

		do_read();
	}

private:
	void do_read() {
		auto self(shared_from_this());

		socket_.async_read_some(boost::asio::buffer(buffer_, buffer_size),
			[this, self](boost::system::error_code ec, std::size_t length) {
				if (!ec) {
					received_ += std::string(buffer_, length);

					// append data received to client traffic
					append_traffic_in(length);

					// retrieve magic number
					if (get_ul_prefix(received_, 1) == p_this_->d_.magic_number_) {
						// retrieve embedded length
						unsigned long length = get_ul_prefix(received_, 3);

						if (length == received_.length()) {
							// all data has been received

							// retrieve message ID
							unsigned long message_id = get_ul_prefix(received_, 2);

							process_received_data(received_, message_id);
							received_.clear();
						}
						else {
							if (length > received_.length())
								do_write(false);	// essential to stay connected
							else {
								last_error_ = "Invalid data received";
								do_write(false);	// essential to stay connected
							}
						}
					}
					else {
						last_error_ = "Invalid data received";
						do_write(false);	// essential to stay connected
					}
				}
				else
					last_error_ = ec.message();
			}
		);
	}

	void do_write(bool write_all) {
		auto self(shared_from_this());

		std::size_t length = 0;

		if (write_all)
			length = data_to_send_.length();

		socket_.async_write_some(
			boost::asio::buffer(data_to_send_.c_str(), length),
			[this, self](boost::system::error_code ec, std::size_t /*length*/) {
				if (!ec)
					do_read();
				else
					last_error_ = ec.message();
			}
		);
	}

	void append_traffic_in(size_t iLen) {
		// append data received to client traffic
		liblec::auto_mutex lock(impl::clients_lock_);
		p_this_->d_.clients_[address_].client_info.traffic.in += iLen;
		p_this_->d_.total_traffic_.in += iLen;
	}

	void append_traffic_out(size_t iLen) {
		// append data received to client traffic
		liblec::auto_mutex lock(impl::clients_lock_);
		p_this_->d_.clients_[address_].client_info.traffic.out += iLen;
		p_this_->d_.total_traffic_.out += iLen;
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
		data_to_send_ = p_this_->on_receive(address_, data);

		if (!data_to_send_.empty()) {
			unsigned long length = static_cast<unsigned long>
				(data_to_send_.length() * sizeof(char))	// space for the actual message
				+ sizeof(unsigned long)					// space for data length
				+ sizeof(unsigned long)					// space for message ID
				+ sizeof(unsigned long);				// space magic number

			// prefix data with it's length
			prefix_with_ul(length, data_to_send_);

			// prefix with message ID
			prefix_with_ul(id, data_to_send_);

			// prefix with magic number
			prefix_with_ul(p_this_->d_.magic_number_, data_to_send_);

			// send data to client
			do_write(true);

			// append data sent to client traffic
			append_traffic_out(length);
		}
		else
			do_write(false);	// essential to stay connected
	}

	boost::asio::ip::tcp::socket socket_;

	enum { buffer_size = 1024 * 64 };
	char buffer_[buffer_size];

	liblec::lecnet::tcp::server_async::client_address address_;
	std::string received_;
	std::string data_to_send_;
	bool denied_;
	std::string last_error_;
	liblec::lecnet::tcp::server_async* p_this_;
};

class liblec::lecnet::tcp::server_async::server_async_ {
public:
	server_async_(boost::asio::ip::address ip,
		short port,
		liblec::lecnet::tcp::server_async* p_this) :
		acceptor_(*p_this->d_.p_io_service_,
			boost::asio::ip::tcp::endpoint(ip, port)),
		socket_(*p_this->d_.p_io_service_),
		p_this_(p_this) {

		do_accept();

		p_this->d_.log(server_log::start(acceptor_.local_endpoint().address().to_string(),
			acceptor_.local_endpoint().port(),
			"Async"));
		p_this->d_.log(server_log::start_info(std::to_string(p_this->d_.get_max_clients())));

		liblec::auto_mutex lock(p_this_->d_.starting_lock_);
		p_this_->d_.starting_ = false;
	}

private:
	void do_accept() {
		acceptor_.async_accept(socket_,
			[this](boost::system::error_code ec) {
				if (!ec) {
					bool deny = false;

					{ // failsafe
						if (p_this_->d_.get_number_of_clients() >= p_this_->d_.get_max_clients())
							deny = true;
					}

					std::make_shared<session_async_>(std::move(socket_), p_this_)->start(deny);
				}

				do_accept();
			});
	}

	boost::asio::ip::tcp::acceptor acceptor_;
	boost::asio::ip::tcp::socket socket_;
	liblec::lecnet::tcp::server_async* p_this_;
};

///////////////////////////////////////////////////////////////////////////////////////////////////
liblec::mutex liblec::lecnet::tcp::server_async::impl::log_locker;
liblec::mutex liblec::lecnet::tcp::server_async::impl::clients_lock_;

liblec::lecnet::tcp::server_async::server_async() :
	d_(*(new impl)) {
	d_.p_tcp_server_ = this;
}

liblec::lecnet::tcp::server_async::~server_async() {
	// stop server
	stop();

	// ensure the async operation is completed before deleting
	if (d_.fut_.valid())
		d_.fut_.get();

	delete& d_;
}

void liblec::lecnet::tcp::server_async::impl::server_func(
	server_async* p_current) {
	try {
		boost::asio::ip::address ip = boost::asio::ip::address::from_string(
			p_current->d_.host_address_);

		server_async_ s(ip, p_current->d_.port_, p_current);
		p_current->d_.p_io_service_->run();
	}
	catch (std::exception& e) {
		p_current->d_.log(e.what());
	}

	liblec::auto_mutex lock(p_current->d_.starting_lock_);
	p_current->d_.starting_ = false;

	// delete io service
	delete p_current->d_.p_io_service_;
	p_current->d_.p_io_service_ = nullptr;
}

bool liblec::lecnet::tcp::server_async::start(const server_params& params) {
	if (running()) {
		// allow only one instance
		d_.log(server_log::server_already_running());
		return true;
	}

	// server_params.server_cert and server_cert_key NOT used in this version
	d_.host_address_ = params.ip;
	d_.port_ = params.port;
	d_.max_clients_ = params.max_clients;
	d_.magic_number_ = params.magic_number;

	try {
		// Create io service.
		d_.p_io_service_ = new boost::asio::io_service;

		// run server task asynchronously
		d_.fut_ = std::async(std::launch::async
			, d_.server_func, this);

		liblec::auto_mutex lock(d_.starting_lock_);
		d_.starting_ = true;
	}
	catch (std::exception& e) {
		d_.log(e.what());
		return false;
	}

	return true;
}

bool liblec::lecnet::tcp::server_async::starting() {
	liblec::auto_mutex lock(d_.starting_lock_);
	return d_.starting_;
}

bool liblec::lecnet::tcp::server_async::running() {
	if (d_.fut_.valid())
		return d_.fut_.wait_for(std::chrono::seconds{ 0 }) != std::future_status::ready;
	else
		return false;
}

void liblec::lecnet::tcp::server_async::close(const client_address& address) {
	liblec::auto_mutex lock(d_.clients_lock_);

	try {
		if (!(d_.clients_.find(address) == d_.clients_.end())) {
			d_.log(server_log::close(std::string(address)));
			boost::asio::ip::tcp::socket* p_socket =
				(boost::asio::ip::tcp::socket*)(d_.clients_[address].p_socket_internal);
			p_socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
			p_socket->close();
		}
		else
			d_.log(server_log::close_error(std::string(address)));
	}
	catch (std::exception& e) {
		d_.log(e.what());
	}
}

void liblec::lecnet::tcp::server_async::close() {
	bool log_this = false;

	try {
		liblec::auto_mutex lock(d_.clients_lock_);

		if (!d_.clients_.empty())
			log_this = true;

		if (log_this)
			d_.log(server_log::close());

		// iterate through map and close client sockets
		for (auto const& it : d_.clients_) {
			boost::asio::ip::tcp::socket* p_socket =
				(boost::asio::ip::tcp::socket*)(d_.clients_[it.first].p_socket_internal);
			p_socket->shutdown(boost::asio::ip::tcp::socket::shutdown_both);
			p_socket->close();
		}
	}
	catch (std::exception& e) {
		d_.log(e.what());
		return;
	}

	// wait for all clients to actually get disconnected
	while (true) {
		boost::this_thread::sleep(boost::posix_time::milliseconds(1));

		liblec::auto_mutex lock(d_.clients_lock_);
		if (!d_.clients_.size())
			break;
	}

	if (log_this)
		d_.log(server_log::closed());
}

bool liblec::lecnet::tcp::server_async::stop() {
	try {
		close();

		if (running()) {
			// stop the io_service
			d_.p_io_service_->stop();

			// wait for server to stop running
			while (running())
				boost::this_thread::sleep(boost::posix_time::milliseconds(1));

			d_.log(server_log::stop());
		}
	}
	catch (std::exception& e) {
		d_.log(e.what());
	}

	return true;
}

void liblec::lecnet::tcp::server_async::get_client_info(std::vector<client_info>& client_info) {
	liblec::auto_mutex lock(d_.clients_lock_);
	client_info.clear();
	client_info.reserve(d_.clients_.size());
	for (auto const& it : d_.clients_)
		client_info.push_back(it.second.client_info);
}

void liblec::lecnet::tcp::server_async::traffic(liblec::lecnet::network_traffic& traffic) {
	liblec::auto_mutex lock(d_.clients_lock_);
	traffic = d_.total_traffic_;
}
