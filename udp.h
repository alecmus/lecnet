/*
** udp.h - udp interface
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

#pragma once

#if defined(LECNET_EXPORTS)
	#include "lecnet.h"
#else
	#include <liblec/lecnet.h>
#endif

#include <string>

namespace liblec {
	namespace lecnet {
		namespace udp {
			namespace broadcast {
				// Correct usage of the liblec::lecnet::udp::broadcast::sender class is as follows:
				//
				// 1. Blocking method
				//
				// liblec::lecnet::udp::broadcast::sender* p_sender =
				//		new liblec::lecnet::udp::broadcast::sender();
				//
				// if (p_sender) {
				//		if (p_sender->do_send()) {
				//			// sending successful
				//		}
				//		else {
				//			// error
				//		}
				// }
				//
				// if (p_sender) {
				//		delete p_sender;
				//		p_sender = nullptr;
				// }
				//
				// 2. Non-blocking method
				//
				// liblec::lecnet::udp::broadcast::sender* p_sender =
				//		new liblec::lecnet::udp::broadcast::sender();
				//
				// if (p_sender) {
				//		if (p_sender->send()) {
				//			while (p_sender->sending()) {
				//				// wait
				//			}
				//
				//			if (p_sender->result()) {
				//				// sending successful
				//			}
				//			else {
				//				// error
				//			}
				//		}
				//		else {
				//			// error
				//		}
				// }
				//
				// if (p_sender) {
				//		delete p_sender;
				//		p_sender = nullptr;
				// }
				//

				/// <summary>
				/// For sending UDP broadcasts.
				/// </summary>
				class lecnet_api sender {
				public:
					/// <summary>
					/// Constructor for the udp_broadcast sender class.
					/// </summary>
					///
					/// <param name="broadcast_port">
					/// The broadcast port. Range is 0 to 65535, e.g. 30001.
					/// </param>
					sender(unsigned short broadcast_port);

					~sender();

					/// <summary>
					/// Sending a broadcast message (synchronously).
					/// </summary>
					///
					/// <param name="message">
					/// The message to be sent.
					/// </param>
					///
					/// <param name="max_count">
					/// The maximum number of times the message is to be sent.
					/// </param>
					///
					/// <param name="timeout_milliseconds">
					/// The timeout between consecutive send operations.
					/// </param>
					///
					/// <param name="actual_count">
					/// The actual number of times the message has been sent.
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
					/// This is a blocking function and will only return when either the sending
					/// operation is complete or when an error occurs.
					/// </remarks>
					bool send(const std::string& message,
						unsigned long max_count,
						long long timeout_milliseconds,
						unsigned long& actual_count,
						std::string& error);

					/// <summary>
					/// Send a broadcast message (asynchronously)
					/// </summary>
					///
					/// <param name="message">
					/// The message to be sent.
					/// </param>
					///
					/// <param name="max_count">
					/// The maximum number of times the message is to be sent.
					/// </param>
					///
					/// <param name="timeout_milliseconds">
					/// The timeout between consecutive send operations.
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
					/// This is a non-blocking function and returns almost immediately. The actual
					/// sending is done on a seperate thread. The status of the message sending can
					/// be checked by calls to <see cref="sending"/> and the results can be
					/// obtained by a call to <see cref="result"/>.
					/// </remarks>
					bool send_async(const std::string& message,
						const unsigned long& max_count,
						const long long& timeout_milliseconds,
						std::string& error);

					/// <summary>
					/// Check if the attempt to send the message is currently underway.
					/// </summary>
					///
					/// <returns>
					/// Returns true if the message sending attempt is currently underway, else
					/// false.
					/// </returns>
					///
					/// <remarks>
					/// This function only works with <see cref="send_async"/>
					/// </remarks>
					bool sending();

					/// <summary>
					/// Check the result of the sending operation.
					/// </summary>
					///
					/// <param name="actual_count">
					/// The actual number of times the message has been sent.
					/// </param>
					///
					/// <param name="error">
					/// Error information.
					/// </param>
					///
					/// <returns>
					/// Returns true if sending the message was successful, else false.
					/// </returns>
					///
					/// <remarks>
					/// Calling this function only makes sense after a successful call to
					/// <see cref="send_async"/> followed by waiting for <see cref="sending"/> to
					/// return false.
					/// </remarks>
					bool result(unsigned long& actual_count,
						std::string& error);

				private:
					class sender_impl;
					sender_impl* d_;

					sender(const sender&);
					sender& operator=(const sender&);
				};

				/// <summary>
				/// For receiving UDP broadcasts.
				/// </summary>
				class lecnet_api receiver {
				public:
					/// <summary>
					/// Constructor for the udp_broadcast receiver class.
					/// </summary>
					///
					/// <param name="broadcast_port">
					/// The broadcast port. Range is 0 to 65535, e.g. 30001.
					/// </param>
					///
					/// <param name="listen_address">
					/// The address to use for listening, e.g. 0.0.0.0.
					/// </param>
					receiver(unsigned short broadcast_port,
						std::string listen_address);
					~receiver();

					/// <summary>
					/// Run the thread that checks for a UDP Broadcast message.
					/// </summary>
					///
					/// <param name="timeout_milliseconds">
					/// The timeout for a receive operation.
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
					/// This function will return almost immediately to avoid blocking for
					/// <paramref name="timeout_milliseconds"/>. The results of the actual
					/// receiving, which will be executed asynchronously, can be obtained by
					/// calling <see cref="get"/>. The status of the receiver thread can be
					/// checked by a call to <see cref="running"/>
					/// </remarks>
					bool run(long long timeout_milliseconds,
						std::string& error);

					/// <summary>
					/// Check if the receiving thread is running, i.e. waiting to receive a
					/// message.
					/// </summary>
					///
					/// <returns>
					/// Returns true if the receiver thread is running, else false.
					/// </returns>
					bool running();

					/// <summary>
					/// Get UDP broadcast message obtained by the last call to <see cref="run"/>.
					/// </summary>
					///
					/// <param name="message">
					/// The message will be written here, if available. A maximum of 1024
					/// characters will be acquired.
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
					/// A call to <see cref="run"/>, and then checking for the status of
					/// <see cref="running"/> is important for this call to make sense. After a
					/// successful call to <see cref="run"/>, wait until <see cref="running"/>
					/// returns false, then call this function. After a message is retrieved using
					/// this function it is immediately deleted from memory. A new call to
					/// <see cref="run"/> can then be used to check for a new message.
					/// </remarks>
					bool get(std::string& message,
						std::string& error);

					/// <summary>
					/// Stop the runner.
					/// </summary>
					///
					/// <remarks>
					/// This function returns almost immediately because all it does it request for
					/// the stop. The internal thread will not be able to respond the same moment.
					/// The caller should check if there was success by calls to
					/// <see cref="running"/>.
					/// </remarks>
					void stop();

				private:
					class receiver_impl;
					receiver_impl* d_;

					receiver(const receiver&);
					receiver& operator=(const receiver&);
				};
			}

			/// <summary>
			/// UDP multicast. For sending or receiving UDP multicasts.
			/// </summary>
			namespace multicast {
				// Correct usage of the liblec::lecnet::udp::multicast::sender class is as follows:
				//
				// 1. Blocking method
				//
				// liblec::lecnet::udp::multicast::sender* p_sender =
				//		new liblec::lecnet::udp::multicast::sender();
				//
				// if (p_sender) {
				//		if (p_sender->do_send()) {
				//			// sending successful
				//		}
				//		else {
				//			// error
				//		}
				// }
				//
				// if (p_sender) {
				//		delete p_sender;
				//		p_sender = nullptr;
				// }
				//
				// 2. Non-blocking method
				//
				// liblec::lecnet::udp::multicast::sender* p_sender =
				//		new liblec::lecnet::udp::multicast::sender();
				//
				// if (p_sender) {
				//		if (p_sender->send()) {
				//			while (p_sender->sending()) {
				//				// wait
				//			}
				//
				//			if (p_sender->result()) {
				//				// sending successful
				//			}
				//			else {
				//				// error
				//			}
				//		}
				//		else {
				//			// error
				//		}
				// }
				//
				// if (p_sender) {
				//		delete p_sender;
				//		p_sender = nullptr;
				// }
				//

				/// <summary>
				/// For sending UDP multicasts.
				/// </summary>
				class lecnet_api sender {
				public:
					/// <summary>
					/// Constructor for the udp_multicast sender class.
					/// </summary>
					///
					/// <param name="multicast_port">
					/// The multicast port. Range is 0 to 65535, e.g. 30001.
					/// </param>
					///
					/// <param name="multicast_address">
					/// The multicast address, e.g. 239.255.0.1 for IPv4 or ff31::8000:1234 for
					/// IPv6.
					/// </param>
					sender(unsigned short multicast_port,
						std::string multicast_address);
					~sender();

					/// <summary>
					/// Sending a multicast message (synchronously).
					/// </summary>
					///
					/// <param name="message">
					/// The message to be sent.
					/// </param>
					///
					/// <param name="max_count">
					/// The maximum number of times the message is to be sent.
					/// </param>
					///
					/// <param name="timeout_milliseconds">
					/// The timeout between consecutive send operations.
					/// </param>
					///
					/// <param name="actual_count">
					/// The actual number of times the message has been sent.
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
					/// This is a blocking function and will only return when either the sending
					/// operation is complete or when an error occurs.
					/// </remarks>
					bool send(const std::string& message,
						unsigned long max_count,
						long long timeout_milliseconds,
						unsigned long& actual_count,
						std::string& error);

					/// <summary>
					/// Send a multicast message (asynchronously)
					/// </summary>
					///
					/// <param name="message">
					/// The message to be sent.
					/// </param>
					///
					/// <param name="max_count">
					/// The maximum number of times the message is to be sent.
					/// </param>
					///
					/// <param name="timeout_milliseconds">
					/// The timeout between consecutive send operations.
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
					/// This is a non-blocking function and returns almost immediately. The actual
					/// sending is done on a seperate thread. The status of the message sending can
					/// be checked by calls to <see cref="sending"/> and the results can be
					/// obtained by a call to <see cref="result"/>.
					/// </remarks>
					bool send_async(const std::string& message,
						const unsigned long& max_count,
						const long long& timeout_milliseconds,
						std::string& error);

					/// <summary>
					/// Check if the attempt to send the message is currently underway.
					/// </summary>
					///
					/// <returns>
					/// Returns true if the message sending attempt is currently underway, else
					/// false.
					/// </returns>
					///
					/// <remarks>
					/// This function only works with <see cref="send_async"/>
					/// </remarks>
					bool sending();

					/// <summary>
					/// Check the result of the sending operation.
					/// </summary>
					///
					/// <param name="actual_count">
					/// The actual number of times the message has been sent.
					/// </param>
					///
					/// <param name="error">
					/// Error information.
					/// </param>
					///
					/// <returns>
					/// Returns true if sending the message was successful, else false.
					/// </returns>
					///
					/// <remarks>
					/// Calling this function only makes sense after a successful call to
					/// <see cref="send_async"/> followed by waiting for <see cref="sending"/> to
					/// return false.
					/// </remarks>
					bool result(unsigned long& actual_count,
						std::string& error);

				private:
					class sender_impl;
					sender_impl* d_;

					sender(const sender&);
					sender& operator=(const sender&);
				};

				// Correct usage of the liblec::lecnet::udp::multicast::receiver class is as
				// follows:
				//
				// liblec::lecnet::udp::multicast::receiver* p_receiver =
				//		new liblec::lecnet::udp::multicast::receiver();
				//
				// if (p_receiver) {
				//		if (p_receiver->run()) {
				//			while (p_receiver->running()) {
				//				// wait
				//			}
				//
				//			std::string message;
				//			if (p_receiver->get(message)) {
				//				// message received
				//			}
				//			else {
				//				// error
				//			}
				//		}
				//		else {
				//			// error
				//		}
				// }
				//
				// if (p_receiver) {
				//		delete p_receiver;
				//		p_receiver = nullptr;
				// }
				//

				/// <summary>
				/// For receiving UDP multicasts.
				/// </summary>
				class lecnet_api receiver {
				public:
					/// <summary>
					/// Constructor for the udp_multicast receiver class.
					/// </summary>
					///
					/// <param name="multicast_port">
					/// The multicast port. Range is 0 to 65535, e.g. 30001.
					/// </param>
					///
					/// <param name="multicast_address">
					/// The multicast address, e.g. 239.255.0.1 for IPv4 or ff31::8000:1234 for
					/// IPv6.
					/// </param>
					///
					/// <param name="listen_address">
					/// The address to use for listening, e.g. 0.0.0.0.
					/// </param>
					receiver(unsigned short multicast_port,
						std::string multicast_address,
						std::string listen_address);
					~receiver();

					/// <summary>
					/// Run the thread that checks for a UDP Broadcast message.
					/// </summary>
					///
					/// <param name="timeout_milliseconds">
					/// The timeout for a receive operation.
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
					/// This function will return almost immediately to avoid blocking for
					/// <paramref name="timeout_milliseconds"/>. The results of the actual
					/// receiving, which will be executed asynchronously, can be obtained by
					/// calling <see cref="get"/>. The status of the receiver thread can be
					/// checked by a call to <see cref="running"/>
					/// </remarks>
					bool run(long long timeout_milliseconds,
						std::string& error);

					/// <summary>
					/// Check if the receiving thread is running, i.e. waiting to receive a
					/// message.
					/// </summary>
					///
					/// <returns>
					/// Returns true if the receiver thread is running, else false.
					/// </returns>
					bool running();

					/// <summary>
					/// Get UDP broadcast message obtained by the last call to <see cref="run"/>.
					/// </summary>
					///
					/// <param name="message">
					/// The message will be written here, if available. A maximum of 1024
					/// characters will be acquired.
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
					/// A call to <see cref="run"/>, and then checking for the status of
					/// <see cref="running"/> is important for this call to make sense. After a
					/// successful call to <see cref="run"/>, wait until <see cref="running"/>
					/// returns false, then call this function. After a message is retrieved using
					/// this function it is immediately deleted from memory. A new call to
					/// <see cref="run"/> can then be used to check for a new message.
					/// </remarks>
					bool get(std::string& message,
						std::string& error);

					/// <summary>
					/// Stop the runner.
					/// </summary>
					///
					/// <remarks>
					/// This function returns almost immediately because all it does it request for
					/// the stop. The internal thread will not be able to respond the same moment.
					/// The caller should check if there was success by calls to
					/// <see cref="running"/>.
					/// </remarks>
					void stop();

				private:
					class receiver_impl;
					receiver_impl* d_;

					receiver(const receiver&);
					receiver& operator=(const receiver&);
				};
			}
		}
	}
}
