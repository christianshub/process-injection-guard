#include "ConsoleColors.h"

void ConsoleColors::SetColor(Color color) {
	SetConsoleTextAttribute(hConsole, color);
}