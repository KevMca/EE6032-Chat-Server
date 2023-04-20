// Copyright 2023 Kevin McAndrew
// Logging source file for writing to a log file with timestamps
//
// Sources:
// tro's answer from: https://stackoverflow.com/questions/7400418/writing-a-log-file-in-c-c

#include "../include/logging.h"

std::string getCurrentDateTime(void) {
    time_t now = time(0);
    struct tm  tstruct;
    char  buf[80];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %X", &tstruct);

    return std::string(buf);
}

void Logger(std::string logMsg, std::string filePath) {
    std::string now = getCurrentDateTime();
    std::ofstream ofs(filePath.c_str(), std::ios_base::out | std::ios_base::app);
    ofs << now << '\t' << logMsg << '\n';
    ofs.close();
}
