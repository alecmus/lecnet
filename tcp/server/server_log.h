/*
** server_log.h - server log interface
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

#include <string>

/// <summary>
/// Server log messages.
/// </summary>
namespace server_log {
	std::string start(std::string ip,
		int port, std::string server_name);

	std::string server_already_running();

	std::string start_info(std::string max_clients);

	std::string stop();

	std::string client_connected(std::string address);

	std::string close();

	std::string closed();

	std::string close(std::string address);

	std::string close_error(std::string address);

	std::string sending_failed(std::string address);

	std::string client_disconnected(std::string address,
		std::string reason);

	std::string client_timeout(std::string address);
};
