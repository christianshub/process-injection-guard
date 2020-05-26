#pragma once
#include <windows.h>

enum Color {
	DarkBlue	= 1,
	Green		= 2,
	Blue		= 3,
	Red			= 4,
	Purple		= 5,
	Gold		= 6,
	White		= 7,
	Grey		= 8
};

class ConsoleColors
{
private:
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

public:
	void SetColor(Color color);
};

