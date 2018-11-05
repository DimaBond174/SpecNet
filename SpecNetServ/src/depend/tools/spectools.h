#ifndef SPECTOOLS_H
#define SPECTOOLS_H

#include <string>
#include <sstream>

template <typename T>
std::string to_string(T value)
{
	std::ostringstream os;
	os << value;
	return os.str();
}



#endif // SPECTOOLS_H
