//
// helper_fxns.cpp - helper functions implementation
//
// lecnet network library, part of the liblec library
// Copyright (c) 2018 Alec Musasa (alecmus at live dot com)
//
// Released under the MIT license. For full details see the
// file LICENSE.txt
//

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
