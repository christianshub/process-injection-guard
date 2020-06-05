#include "ConfigParser.h"

unsigned int ParseNumerics(const std::string num)
{
	if (num != "1")
	{
		return 0;
	}

	return 1;
}

std::vector<std::string> ParseSignatures(const std::string signatures)
{
	std::vector<std::string> container = {};
	std::string sig = signatures;

	// To lower case
	ToLowercase(sig);

	// Remove spaces
	ReplaceAllSubStr(sig, " ", "");

	// Check for non-hex
	if (sig.find_first_not_of("abcdef0123456789,?") != std::string::npos)
	{
		std::cout << "Error, signature can only contain hex letters and numbers: abcdef0123456789" << std::endl;
		std::exit(1);
	}

	// Insert signatures into container
	std::stringstream ss(sig);
	while (ss.good()) {
		std::string substr;
		std::getline(ss, substr, ',');
		container.push_back(substr);
	}

	// Make sure each sig is divisble by 2.
	for (size_t i = 0; i < container.size(); i++)
	{
		if (container[i].length() % 2 != 0)
		{
			std::cout << "Incorrect signature size" << std::endl;
			std::exit(1);
		}
	}

	return container;
}


std::vector<std::string> ParseModuleNames(const std::string names)
{
	std::vector<std::string> ModNames = {};
	std::string name = names;

	// Remove spaces
	ReplaceAllSubStr(name, " ", "");

	// Insert signatures into container
	std::stringstream ss(name);
	while (ss.good()) {
		std::string substr;
		std::getline(ss, substr, ',');
		ModNames.push_back(substr);
	}

	return ModNames;
}