/*
** helper_fxns.cpp - helper functions implementation
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

#include "helper_fxns.h"

#include <boost/date_time/posix_time/posix_time.hpp>

std::string time_stamp() {
	boost::posix_time::ptime now = boost::posix_time::second_clock::local_time();
	std::string time_stamp = boost::posix_time::to_iso_extended_string(now);

	// eliminate the time seperator (T)
	size_t pos = 0;
	if ((pos = time_stamp.find('T', pos)) != std::string::npos)
		time_stamp.replace(pos, 1, " ");

	return time_stamp;
}
