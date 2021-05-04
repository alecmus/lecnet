/*
** helper_fxns.h - helper functions interface
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
#include <cmath>

/// <summary>
/// Make timestamp from current time.
/// </summary>
/// 
/// <returns>
/// Returns a timestamp in the form in the form 2018-12-30 14:38:15.
/// </returns>
std::string time_stamp();

/// <summary>
/// Get the maximum prefix size.
/// </summary>
static inline double max_prefix_size() {
	return std::pow(2, 8 * sizeof(unsigned long)) - 1;
}

/// <summary>
/// Prefix a string with an unsigned long, in the form 'xxxxdata'
/// </summary>
/// 
/// <remarks>
/// Maximum size of prefix is 2^(8 * sizeof(unsigned long)) - 1,
/// which is 4'294'967'295 bytes (4 GB) since an unsigned long is 4 bytes.
/// </remarks>
static inline void prefix_with_ul(const unsigned long prefix,
	std::string& data) {
	// insert placeholder for the unsigned long prefix
	for (size_t i = 0; i < sizeof(unsigned long); i++)
		data = "x" + data;

	// get buffer
	char* buffer = (char*)(const char*)data.c_str();

	// replace the placeholder with the unsigned long
	((unsigned long*)buffer)[0] = prefix;
}

/// <summary>
/// Get the unsigned long prefix in a string.
/// </summary>
/// 
/// <param name="data">
/// The string in the form xxxxyyyyzzzzdata
/// where xxxx, yyyy and zzzz contain a unsigned long prefix.
/// </param>
/// 
/// <param name="position">
/// The position of the unsigned long, starting from 1. e.g. in xxxxyyyyzzzzdata, xxxx is in
/// position 1, yyyy in position 2, and zzzz in position 3
/// </param>
/// 
/// <returns>
/// Returns the unsigned long prefix
/// </returns>
static inline unsigned long get_ul_prefix(const std::string& data,
	unsigned long position) {
	std::string s(data, (position - 1) * sizeof(unsigned long), sizeof(unsigned long));
	return *(unsigned long*)s.c_str();
}

/// <summary>
/// Get the unsigned long prefix in a string. Prefix is 'xxxx' in a string of the form 'xxxxdata'
/// </summary>
/// 
/// <returns>
/// Returns the unsigned long prefix
/// </returns>
/// 
/// <remarks>
/// This function removes the unsigned long in 'xxxxdata' to leave only 'data'
/// </remarks>
static inline unsigned long get_ul_prefix(std::string& data) {
	// retrieve prefix
	std::string s(data, 0, sizeof(unsigned long));
	unsigned long prefix = *(unsigned long*)s.c_str();

	// erase prefix
	data.erase(0, sizeof(unsigned long));

	return prefix;
}

/// <summary>
/// Compare two strings.
/// </summary>
/// 
/// <remarks>
/// Not case sensitive. For use with alphabetical sorting using the std::sort() method.
/// </remarks>
static inline bool compare_no_case(std::string first,
	std::string second) {
	size_t i = 0;
	while ((i < first.length()) && (i < second.length()))
	{
		if (tolower(first[i]) < tolower(second[i]))
			return true;
		else
			if (tolower(first[i]) > tolower(second[i]))
				return false;
		i++;
	}

	if (first.length() < second.length())
		return true;
	else
		return false;
}
