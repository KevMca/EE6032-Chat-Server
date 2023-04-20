// Copyright 2023 Kevin McAndrew
// Logging header file for writing to a log file with timestamps
//
// Sources:
// tro's answer from: https://stackoverflow.com/questions/7400418/writing-a-log-file-in-c-c

#ifndef LOGGING_H_
#define LOGGING_H_

#include <string>
#include <ctime>
#include <fstream>

// Returns the current time and date as a string
std::string getCurrentDateTime(void);

// Constructor for server if private and public keys are known
// Inputs -> privateName: location of the private key file for the server
//           publicName: location of the public key file for the server
void Logger(std::string logMsg, std::string filePath);

#endif  // LOGGING_H_
