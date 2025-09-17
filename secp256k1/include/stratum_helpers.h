#ifndef STRATUM_HELPERS_H
#define STRATUM_HELPERS_H

#include <string>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <cctype>
#include <boost/multiprecision/cpp_int.hpp>

std::vector<uint8_t> HexToBytes(const std::string & hex);
std::string BytesToHexBE(const std::vector<uint8_t> & bytes);
std::string DecToUint256HexBE(const std::string & dec);
std::string BeHexToLeHex(const std::string & beHex64);
std::vector<uint8_t> AssembleWork(const std::string & msgHex,
                                 const std::string & ex1Hex,
                                 const std::string & ex2Hex,
                                 size_t ex2SizeBytes);
std::string PoolBoundaryFromDifficultyBE(double shareDiff);

#endif // STRATUM_HELPERS_H
