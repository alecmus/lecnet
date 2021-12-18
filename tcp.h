//
// tcp.h - tcp/ip interface
//
// lecnet network library, part of the liblec library
// Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
//
// Released under the MIT license. For full details see the
// file LICENSE.txt
//

#pragma once

#if defined(LECNET_EXPORTS)
	#include "lecnet.h"
#else
	#include <liblec/lecnet.h>
#endif

#include <string>
#include <vector>
#include <functional>

namespace liblec {
	namespace lecnet {
		/// <summary>
		/// For TCP network connections.
		/// </summary>
		namespace tcp {
			/// <summary>
			/// Get the IP addresses of the host machine.
			/// </summary>
			///
			/// <param name="ips">
			/// The list of available IP addresses.
			/// </param>
			///
			/// <param name="error">
			/// Error information.
			/// </param>
			void lecnet_api get_host_ips(std::vector<std::string>& ips);

			// Correct usage of the liblec::lecnet::tcp::client class is as follows:
			//
			// if (connect()) {
			//		while (connecting()) {
			//			// wait
			//		}
			//
			//		if (connected()) {
			//			while (running()) {
			//				// use server-client connection
			//			}
			//		}
			//		else {
			//			// connection error
			//		}
			// }
			// else {
			//		// connection error
			// }
			//
			// While running() is true, there are two ways of using the server-client connection
			//
			// 1. Blocking method (faster)
			//
			// auto busy_function = []() {
			//		// wait
			//		return true;
			// };
			//
			// std::string send, received;
			// if (send_data(send, received, busy_function)) {
			//		// use received data
			// }
			// else {
			//		// send/receive error
			// }
			//
			// 2. Non-blocking method (slower)
			//
			// std::string send, received;
			// unsigned long data_id;
			// if (send_data_async(send, received, data_id) {
			//		while (sending(data_id)) {
			//			// wait
			//		}
			//
			//		if (get_response(data_id, received)) {
			//			// use received data
			//		}
			//		else {
			//			// send/receive error
			//		}
			// }
			//

			/// <summary>
			/// TCP client.
			/// </summary>
			class lecnet_api client {
			public:
				struct client_params {
					/// <param name="address">
					/// The server address, e.g. 127.0.0.1.
					/// </param>
					std::string address = "127.0.0.1";

					/// <param name="port">
					/// The port to use. Range is 0 to 65535, e.g. 50000.
					/// </param>
					unsigned short port = 50001;

					/// <param name="timeout_seconds">
					/// The connect operation timeout in seconds, e.g. 5.
					/// </param>
					long timeout_seconds = 10;

					/// <param name="use_ssl">
					/// Whether to use SSL encryption.
					/// </param>
					bool use_ssl = true;

					/// <param name="ca_cert_path">
					/// The full path to the CA Certificate, if <see cref="use_ssl"/> is set to true.
					/// </param>
					std::string ca_cert_path = "ca.crt";

					/// <summary>
					/// The magic number for prefixing data (must match with server). Useful for
					/// checking data integrity.
					/// </summary>
					unsigned long magic_number = 0;
				};

				client();
				~client();

				/// <summary>
				/// Connect to a TCP server.
				/// </summary>
				///
				/// <param name="params">
				/// Server parameters, as defined in the client_params struct.
				/// </param>
				///
				/// <param name="error">
				/// Error information.
				/// </param>
				///
				/// <returns>
				/// Returns true if the client thread was created successfully, else false.
				/// </returns>
				///
				/// <remarks>
				/// Note that this function returns almost immediately. The actual connection
				/// attempt is made on the client thread. To establish the result of the
				/// connection attempt wait for <see cref="connecting"/> to return false and then
				/// check the status of <see cref="connected"/>. Any error encountered in the
				/// connection attempt will be written to the error parameter of
				/// <see cref="connected"/>.
				/// </remarks>
				bool connect(const client_params& params,
					std::string& error);

				/// <summary>
				/// Check if the client is currently trying to connect to a server.
				/// </summary>
				///
				/// <returns>
				/// Returns true if the client is in the process of trying to connect to a server,
				/// else false.
				/// </returns>
				///
				/// <remarks>
				/// After true is returned by <see cref="connect"/>, wait until false is returned
				/// by this function, then call <see cref="connected"/> to establish if the
				/// connection was successful.
				/// </remarks>
				bool connecting();

				/// <summary>
				/// Check if the client is connected to a server.
				/// </summary>
				///
				/// <param name="error">
				/// Error information. Note: do not assume this contains any error information
				/// just because the client is not connected, e.g. when this function is called
				/// immediately after <see cref="connect"/> but before the actual connection is
				/// established (in this case false will be returned but error will be empty).
				/// If this function is called immediately after false is returned from
				/// <see cref="connecting"/> and it returns false as well, then error is
				/// guaranteed to have some information about why the connection attempt failed.
				/// Error information is erased from memory immediately after a call to this
				/// function.
				/// </param>
				///
				/// <returns>
				/// Returns true if client is connected to a server, else false.
				/// </returns>
				///
				/// <remarks>
				/// It only makes sense to call this function after a successful call to
				/// <see cref="connect"/> and waiting until false is returned from
				/// <see cref="connecting"/>.
				/// </remarks>
				bool connected(std::string& error);

				/// <summary>
				/// Check if the client thread is running.
				/// </summary>
				///
				/// <returns>
				/// Returns true if the client thread is running, else false.
				/// </returns>
				///
				/// <remarks>
				/// This function is useful to check if the client is still connected to the server
				/// after true is returned from <see cref="connected"/>. Once false is returned
				/// you can be sure the connection has been lost and a call to
				/// <see cref="connect"/> is required to reestablish the connection.
				/// </remarks>
				bool running();

				/// <summary>
				/// Send data to the server (synchronously).
				/// </summary>
				///
				/// <param name="data">
				/// The data to be sent.
				/// </param>
				///
				/// <param name="received">
				/// The feedback data received from the server.
				/// </param>
				///
				/// <param name="timeout_seconds">
				/// The timeout of the send/receive operation, in seconds.
				/// </param>
				///
				/// <param name="busy_function">
				/// The function to call repeatedly during the send/receive operation (which can
				/// possibly timeout depending on the server availability, load and configuration).
				/// </param>
				///
				/// <param name="error">
				/// Error information.
				/// </param>
				///
				/// <returns>
				/// Returns true if the operation is successful, else false.
				/// </returns>
				///
				/// <remarks>
				/// This is a blocking operation.
				/// </remarks>
				bool send_data(const std::string& data,
					std::string& received,
					const long& timeout_seconds,
					std::function<bool()> busy_function,
					std::string& error);

				/// <summary>
				/// Send data to the server (asyncronously).
				/// </summary>
				///
				/// <param name="data">
				/// The data to be sent.
				/// </param>
				///
				/// <param name="timeout_seconds">
				/// The timeout of the send/receive operation, in seconds.
				/// </param>
				///
				/// <param name="data_id">
				/// The unique ID of the data being sent. This will be required in the
				/// subsequent calls to <see cref="sending"/> and <see cref="get_response"/>.
				/// </param>
				///
				/// <param name="error">
				/// Error information.
				/// </param>
				///
				/// <returns>
				/// Returns true if the operation is successful, else false.
				/// </returns>
				///
				/// <remarks>
				/// This is a non-blocking operation and the function returns almost immediately.
				/// The actual sending will be executed asynchronously and the progress can be
				/// known through <see cref="sending"/>. Note, however, that this process is
				/// somewhat slower than using <see cref="send_data"/>.
				/// </remarks>
				bool send_data_async(const std::string& data,
					const long& timeout_seconds,
					unsigned long& data_id,
					std::string& error);

				/// <summary>
				/// Check if the data is still being sent.
				/// </summary>
				///
				/// <param name="data_id">
				/// The unique ID associated with the data.
				/// </param>
				///
				/// <returns>
				/// Returns true if the data is still being sent, else false.
				/// </returns>
				bool sending(const unsigned long& data_id);

				/// <summary>
				/// Get the server response.
				/// </summary>
				///
				/// <param name="data_id">
				/// The unique ID associated with the data that was sent.
				/// </param>
				///
				/// <param name="received">
				/// The data received from the server.
				/// </param>
				///
				/// <param name="error">
				/// Error information.
				/// </param>
				///
				/// <returns>
				/// Returns true if successful, else false.
				/// </returns>
				///
				/// <remarks>
				/// A call to <see cref="send_data_async"/>, and then checking for the status of
				/// <see cref="sending"/> is important for this call to make sense. After a
				/// successful call to <see cref="send_data_async"/>, wait until
				/// <see cref="sending"/> returns false, then call this function. After the
				/// response is retrieved using this function it is immediately deleted from
				/// memory. A new call to <see cref="send_data_async"/> can then be used before
				/// checking for another response.
				/// </remarks>
				bool get_response(const unsigned long& data_id,
					std::string& received,
					std::string& error);

				/// <summary>
				/// Disconnect from server.
				/// </summary>
				void disconnect();

				/// <summary>
				/// Get the total network traffic for this client.
				/// </summary>
				///
				/// <param name="traffic">
				/// The total network traffic.
				/// </param>
				void traffic(liblec::lecnet::network_traffic& traffic);

			private:
				class impl;
				impl& _d;

				class client_async;
				class client_async_ssl;

				client(const client&) = delete;
				client& operator=(const client&) = delete;
			};

			// Correct usage of the liblec::lecnet::tcp::server class is as follows:
			//
			// 1. Make a new class and inherit from liblec::lecnet::tcp::server_async and
			// liblec::lecnet::tcp::server_async_ssl. In the inherited classes provide
			// implementations for the log() and on_receive() virtual functions
			//
			// class my_server_class : public liblec::lecnet::tcp::server_async {
			// public:
			//		my_server_class() {};
			//		~my_server_class() {};
			//
			//		void log(const std::string& time_stamp,
			//			const std::string& event) {
			//			// implementation for log member. Below is a simple example
			//			std::cout << time_stamp << "\t" << event << std::endl;
			//		}
			//
			//		std::string on_receive(const client_address& address,
			//			const std::string& data_received) {
			//			// implementation for on_receive member. Below is a simple example
			//			return data_received;	// simple echo server
			//		}
			// }
			//
			// class my_server_class_ssl : public liblec::lecnet::tcp::server_async_ssl {
			//		...
			// }
			//
			// 2. Declare a pointer to the server base class and use it as follows
			//
			// liblec::lecnet::tcp::server* p_server = nullptr;
			//
			// bool use_ssl = ...;
			//
			// if (use_ssl)
			//		p_server = new my_server_class_ssl();
			// else
			//		p_server = new my_server_class();
			//
			// 3. Proceed as follows
			//
			// if (p_server->start()) {
			//		while (p_server->starting()) {
			//			// wait
			//		}
			//
			//		while (p_server->running()) {
			//			// main server loop
			//		}
			// }
			// else {
			//		// error
			// }
			//
			// if (p_server) {
			//		delete p_server;
			//		p_server = nullptr;
			// }
			//

			/// <summary>
			/// Base class for TCP servers.
			/// </summary>
			class lecnet_api server {
			public:
				server() {}
				virtual ~server() {}

				/// <summary>
				/// Client network address.
				/// </summary>
				typedef std::string client_address;

				/// <summary>
				/// Client information.
				/// </summary>
				struct client_info {
					/// <summary>
					/// Client's network address.
					/// </summary>
					client_address address;

					/// <summary>
					/// Client's network traffic.
					/// </summary>
					liblec::lecnet::network_traffic traffic;
				};

				/// <summary>
				/// Server parameters.
				/// </summary>
				struct server_params {
					/// <summary>
					/// Server IP address.
					/// </summary>
					std::string ip = "0.0.0.0";

					/// <summary>
					/// Server port.
					/// </summary>
					unsigned short port = 50001;

					/// <summary>
					/// The maximum number of clients that the server should accept.
					/// </summary>
					unsigned short max_clients = 1000;

					/// <summary>
					/// The server certificate.
					/// </summary>
					std::string server_cert = "server.crt";

					/// <summary>
					/// The server certificate's private key.
					/// </summary>
					std::string server_cert_key = "server.crt";

					/// <summary>
					/// The server certificate's password.
					/// </summary>
					std::string server_cert_key_password = "password";

					/// <summary>
					/// The magic number for prefixing data (must match with client). Useful for
					/// checking data integrity.
					/// </summary>
					unsigned long magic_number = 0;
				};

				/// <summary>
				/// Start server.
				/// </summary>
				///
				/// <param name="params">
				/// Server parameters, as defined in the ServerParams struct.
				/// </param>
				///
				/// <returns>
				/// Returns true if successful or if server is already running, else false.
				/// </returns>
				///
				/// <remarks>
				/// Should return immediately. Run actual server on a seperate thread.
				/// </remarks>
				virtual bool start(const server_params& params) = 0;

				/// <summary>
				/// Check if the server is currently in the process of starting.
				/// </summary>
				///
				/// <returns>
				/// Returns true if server is starting, else false.
				/// </returns>
				virtual bool starting() = 0;

				/// <summary>
				/// Check whether this server is running.
				/// </summary>
				///
				/// <returns>
				/// Returns true if the server is running, else false.
				/// </returns>
				virtual bool running() = 0;

				/// <summary>
				/// Close a connection.
				/// </summary>
				///
				/// <param name="address">
				/// The address of the client to disconnect.
				/// </param>
				///
				/// <remarks>
				/// Client can re-connect because the server is still running.
				/// </remarks>
				virtual void close(const client_address& address) = 0;

				/// <summary>
				/// Close all connections.
				/// </summary>
				///
				/// <remarks>
				/// Clients can re-connect because the server is still running.
				/// </remarks>
				virtual void close() = 0;

				/// <summary>
				/// Stop server.
				/// </summary>
				///
				/// <returns>
				/// Returns true if successful, else false.
				/// </returns>
				///
				/// <remarks>
				/// Clients cannot reconnect until the server is restarted by a fresh call to
				/// <see cref="start"/>.
				/// </remarks>
				virtual bool stop() = 0;

				/// <summary>
				/// Get information of currently connected clients.
				/// </summary>
				///
				/// <param name="clients_info">
				/// The list of client information.
				/// </param>
				virtual void get_client_info(std::vector<client_info>& clients_info) = 0;

				/// <summary>
				/// Get total network traffic.
				/// </summary>
				///
				/// <param name="traffic">
				/// The total traffic.
				/// </param>
				virtual void traffic(liblec::lecnet::network_traffic& traffic) = 0;

				/// <summary>
				/// Called whenever an event is logged.
				/// </summary>
				///
				/// <param name="time_stamp">
				/// The event's timestamp.
				/// </param>
				///
				/// <param name="event">
				/// A description of the event.
				/// </param>
				///
				/// <remarks>
				/// Make sure the code is non-blocking. The function should return almost
				/// immediately.
				/// </remarks>
				virtual void log(const std::string& time_stamp,
					const std::string& event) = 0;

				/// <summary>
				/// Called whenever data is received.
				/// </summary>
				///
				/// <param name="address">
				/// The address of the client.
				/// </param>
				///
				/// <param name="data_received">
				/// The data received from the client.
				/// </param>
				///
				/// <returns>
				/// The data to send back to the client.
				/// </returns>
				///
				/// <remarks>
				/// The sooner this function returns the faster the asynchronous server.
				/// </remarks>
				virtual std::string on_receive(const client_address& address,
					const std::string& data_received) = 0;

			private:
				server(const server&) = delete;
				server& operator=(const server&) = delete;
			};

			/// <summary>
			/// Asynchronous (event driven) TCP server class WITHOUT encryption.
			/// </summary>
			///
			/// <remarks>
			/// Based on boost asio. Uses a single thread (event driven). This class does not use
			/// any encryption. As such, use it with care. Avoid using it on an unsecure network.
			/// </remarks>
			class lecnet_api server_async : public server {
			public:
				server_async();
				virtual ~server_async();

				/// <summary>
				/// Start server.
				/// </summary>
				///
				/// <param name="params">
				/// Server parameters, as defined in the server_params struct.
				/// </param>
				///
				/// <returns>
				/// Returns true if successful or if server is already running, else false.
				/// </returns>
				///
				/// <remarks>
				/// server_cert and server_cert_key NOT used by this version.
				/// </remarks>
				bool start(const server_params& params);

				/// <summary>
				/// Check if the server is currently in the process of starting.
				/// </summary>
				///
				/// <returns>
				/// Returns true if server is starting, else false.
				/// </returns>
				bool starting();

				/// <summary>
				/// Check whether this server is running.
				/// </summary>
				///
				/// <returns>
				/// Returns true if the server is running, else false.
				/// </returns>
				bool running();

				/// <summary>
				/// Close a connection.
				/// </summary>
				///
				/// <param name="address">
				/// The address of the client to disconnect.
				/// </param>
				///
				/// <remarks>
				/// Client can re-connect because the server is still running.
				/// </remarks>
				void close(const client_address& address);

				/// <summary>
				/// Close all connections.
				/// </summary>
				///
				/// <remarks>
				/// Clients can re-connect because the server is still running.
				/// </remarks>
				void close();

				/// <summary>
				/// Stop server.
				/// </summary>
				///
				/// <returns>
				/// Returns true if successful, else false.
				/// </returns>
				///
				/// <remarks>
				/// Clients cannot reconnect until the server is restarted by a fresh call to
				/// <see cref="start"/>.
				/// </remarks>
				bool stop();

				/// <summary>
				/// Get information of currently connected clients.
				/// </summary>
				///
				/// <param name="clients_info">
				/// The list of client information.
				/// </param>
				void get_client_info(std::vector<client_info>& client_info);

				/// <summary>
				/// Get total network traffic.
				/// </summary>
				///
				/// <param name="traffic">
				/// The total traffic.
				/// </param>
				void traffic(liblec::lecnet::network_traffic& traffic);

				/// <summary>
				/// Called whenever an event is logged.
				/// </summary>
				///
				/// <param name="time_stamp">
				/// The event's timestamp.
				/// </param>
				///
				/// <param name="event">
				/// A description of the event.
				/// </param>
				///
				/// <remarks>
				/// Make sure the code is non-blocking. The function should return almost
				/// immediately.
				/// </remarks>
				virtual void log(const std::string& time_stamp,
					const std::string& event) { return; };

				/// <summary>
				/// Called whenever data is received.
				/// </summary>
				///
				/// <param name="address">
				/// The address of the client.
				/// </param>
				///
				/// <param name="data_received">
				/// The data received from the client.
				/// </param>
				///
				/// <returns>
				/// The data to send back to the client.
				/// </returns>
				///
				/// <remarks>
				/// The sooner this function returns the faster the asynchronous server.
				/// </remarks>
				virtual std::string on_receive(const client_address& address,
					const std::string& data_received) { return std::string(); };

			private:
				class impl;
				impl& _d;

				class _session_async;
				class _server_async;

				server_async(const server_async&) = delete;
				server_async& operator=(const server_async&) = delete;
			};

			/// <summary>
			/// Asynchronous (event driven) TCP server class WITH SSL encryption.
			/// </summary>
			///
			/// <remarks>
			/// Based on boost asio. Uses a single thread (event driven).
			/// </remarks>
			class lecnet_api server_async_ssl : public server {
			public:
				server_async_ssl();
				virtual ~server_async_ssl();

				/// <summary>
				/// Start server.
				/// </summary>
				///
				/// <param name="params">
				/// Server parameters, as defined in the ServerParams struct.
				/// </param>
				///
				/// <returns>
				/// Returns true if successful or if server is already running, else false.
				/// </returns>
				///
				/// <remarks>
				/// If server_cert_key is not specified key file is sought in server_cert
				/// </remarks>
				bool start(const server_params& params);

				/// <summary>
				/// Check if the server is currently in the process of starting.
				/// </summary>
				///
				/// <returns>
				/// Returns true if server is starting, else false.
				/// </returns>
				bool starting();

				/// <summary>
				/// Check whether this server is running.
				/// </summary>
				///
				/// <returns>
				/// Returns true if the server is running, else false.
				/// </returns>
				bool running();

				/// <summary>
				/// Close a connection.
				/// </summary>
				///
				/// <param name="address">
				/// The address of the client to disconnect.
				/// </param>
				///
				/// <remarks>
				/// Client can re-connect because the server is still running.
				/// </remarks>
				void close(const client_address& address);

				/// <summary>
				/// Close all connections.
				/// </summary>
				///
				/// <remarks>
				/// Clients can re-connect because the server is still running.
				/// </remarks>
				void close();

				/// <summary>
				/// Stop server.
				/// </summary>
				///
				/// <returns>
				/// Returns true if successful, else false.
				/// </returns>
				///
				/// <remarks>
				/// Clients cannot reconnect until the server is restarted by a fresh call to
				/// <see cref="start"/>.
				/// </remarks>
				bool stop();

				/// <summary>
				/// Get information of currently connected clients.
				/// </summary>
				///
				/// <param name="clients_info">
				/// The list of client information.
				/// </param>
				void get_client_info(std::vector<client_info>& client_info);

				/// <summary>
				/// Get total network traffic.
				/// </summary>
				///
				/// <param name="traffic">
				/// The total traffic.
				/// </param>
				void traffic(liblec::lecnet::network_traffic& traffic);

				/// <summary>
				/// Called whenever an event is logged.
				/// </summary>
				///
				/// <param name="time_stamp">
				/// The event's timestamp.
				/// </param>
				///
				/// <param name="event">
				/// A description of the event.
				/// </param>
				///
				/// <remarks>
				/// Make sure the code is non-blocking. The function should return almost
				/// immediately.
				/// </remarks>
				virtual void log(const std::string& time_stamp,
					const std::string& event) { return; };

				/// <summary>
				/// Called whenever data is received.
				/// </summary>
				///
				/// <param name="address">
				/// The address of the client.
				/// </param>
				///
				/// <param name="data_received">
				/// The data received from the client.
				/// </param>
				///
				/// <returns>
				/// The data to send back to the client.
				/// </returns>
				///
				/// <remarks>
				/// The sooner this function returns the faster the asynchronous server.
				/// </remarks>
				virtual std::string on_receive(const client_address& address,
					const std::string& data_received) { return std::string(); };

			private:
				class impl;
				impl& _d;

				class _session_async_ssl;
				class _server_async_ssl;

				server_async_ssl(const server_async_ssl&) = delete;
				server_async_ssl& operator=(const server_async_ssl&) = delete;
			};
		}
	}
}
