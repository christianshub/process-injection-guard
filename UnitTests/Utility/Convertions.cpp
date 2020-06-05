#include "Convertions.h"

std::string INT_TO_HEXSTRING(int input) {
	std::stringstream stream;
	stream << std::hex << input;
	return stream.str();
}

std::string PCWSTR_TO_STRING(PCWSTR string) {

	std::setlocale(LC_ALL, "");
	const std::wstring ws(string);
	const std::locale locale("");
	typedef std::codecvt<wchar_t, char, std::mbstate_t> converter_type;
	const converter_type& converter = std::use_facet<converter_type>(locale);
	std::vector<char> to(ws.length() * converter.max_length());
	std::mbstate_t state;
	const wchar_t* from_next;
	char* to_next;
	const converter_type::result result = converter.out(state, ws.data(), ws.data() + ws.length(), from_next, &to[0], &to[0] + to.size(), to_next);

	if (result == converter_type::ok || result == converter_type::noconv) {
		const std::string str(&to[0], to_next);
		return str;
	}

	throw "PCWSTR_TO_STRING convertion error";
}

std::string PBYTE_TO_HEXSTR(PBYTE data, int len)
{
	std::stringstream ss;
	ss << std::hex;

	for (int i(0); i < len; ++i)
		ss << std::setw(2) << std::setfill('0') << (int)data[i];

	return ss.str();
}

char* PWCHAR_T_TO_PCHAR(wchar_t* string)
{
	size_t len = wcslen(string) + 1;
	char* c_string = new char[len];
	size_t numCharsRead;
	wcstombs_s(&numCharsRead, c_string, len, string, _TRUNCATE);
	return c_string;
}

std::string WSTRING_TO_STRING(std::wstring internal)
{
	auto& f = std::use_facet<std::codecvt<wchar_t, char, std::mbstate_t>>(std::locale());

	std::mbstate_t mb{}; // initial shift state
	std::string external(internal.size() * f.max_length(), '\0');
	const wchar_t* from_next;
	char* to_next;
	f.out(mb, &internal[0], &internal[internal.size()], from_next,
		&external[0], &external[external.size()], to_next);
	// error checking skipped for brevity
	external.resize(to_next - &external[0]);

	return external;
}