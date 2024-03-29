//
// server_log.cpp - server log implementation
//
// lecnet network library, part of the liblec library
// Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
//
// Released under the MIT license. For full details see the
// file LICENSE.txt
//

#include "server_log.h"

std::string server_log::start(std::string ip,
	int port, std::string server_name) {
	return "Server listening: " + ip + ":" + std::to_string(port) + " (" + server_name + ") ... ";
}

std::string server_log::server_already_running() {
	return "Server already running";
}

std::string server_log::start_info(std::string max_clients) {
	std::string s;
	s += "Clients: Max " + max_clients;
	return s;
}

std::string server_log::stop() {
	return "Server stopped";
}

std::string server_log::client_connected(std::string address) {
	return address + " - connected";
}

std::string server_log::close() {
	return "Closing all connections ...";
}

std::string server_log::closed() {
	return "All connections closed";
}

std::string server_log::close(std::string address) {
	return address + " - closing connection ...";
}

std::string server_log::close_error(std::string address) {
	return address + " - invalid address";
}

std::string server_log::sending_failed(std::string address) {
	return address + " - sending data failed";
}

std::string server_log::client_disconnected(std::string address,
	std::string reason) {
	if (reason.empty())
		return address + " - disconnected";
	else
		return address + " - disconnected [" + reason + "]";
}

std::string server_log::client_timeout(std::string address) {
	return address + " - timeout";
}
