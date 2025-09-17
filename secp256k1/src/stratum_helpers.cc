#include "../include/stratum_helpers.h"

using boost::multiprecision::cpp_int;

static inline uint8_t HexNib(char c)
{
    if (c >= '0' && c <= '9') return uint8_t(c - '0');
    c = std::tolower(static_cast<unsigned char>(c));
    if (c >= 'a' && c <= 'f') return uint8_t(c - 'a' + 10);
    throw std::invalid_argument("bad hex character");
}

std::vector<uint8_t> HexToBytes(const std::string & hex)
{
    if (hex.size() % 2) throw std::invalid_argument("hex length odd");
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2)
    {
        out.push_back((HexNib(hex[i]) << 4) | HexNib(hex[i + 1]));
    }
    return out;
}

std::string BytesToHexBE(const std::vector<uint8_t> & bytes)
{
    static const char * tab = "0123456789abcdef";
    std::string out(bytes.size() * 2, '0');
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        out[2 * i] = tab[(bytes[i] >> 4) & 0xF];
        out[2 * i + 1] = tab[bytes[i] & 0xF];
    }
    return out;
}

std::string DecToUint256HexBE(const std::string & dec)
{
    cpp_int x = 0;
    for (char c : dec)
    {
        if (!std::isdigit(static_cast<unsigned char>(c))) throw std::invalid_argument("bad dec character");
        x = x * 10 + (c - '0');
    }
    std::vector<uint8_t> be(32, 0);
    cpp_int t = x;
    for (int i = 31; i >= 0; --i)
    {
        be[i] = static_cast<uint8_t>((t & 0xFF).convert_to<unsigned>());
        t >>= 8;
    }
    return BytesToHexBE(be);
}

std::string BeHexToLeHex(const std::string & beHex)
{
    if (beHex.size() != 64) throw std::invalid_argument("need 64 hex chars");
    std::string out(64, '0');
    for (int i = 0; i < 32; ++i)
    {
        out[2 * i] = beHex[64 - 2 * (i + 1)];
        out[2 * i + 1] = beHex[64 - 2 * (i + 1) + 1];
    }
    return out;
}

std::vector<uint8_t> AssembleWork(const std::string & msgHex,
                                  const std::string & ex1Hex,
                                  const std::string & ex2Hex,
                                  size_t ex2SizeBytes)
{
    if (ex2Hex.size() != ex2SizeBytes * 2)
    {
        throw std::invalid_argument("extraNonce2 wrong length");
    }
    auto msg = HexToBytes(msgHex);
    auto ex1 = HexToBytes(ex1Hex);
    auto ex2 = HexToBytes(ex2Hex);
    std::vector<uint8_t> work;
    work.reserve(msg.size() + ex1.size() + ex2.size());
    work.insert(work.end(), msg.begin(), msg.end());
    work.insert(work.end(), ex1.begin(), ex1.end());
    work.insert(work.end(), ex2.begin(), ex2.end());
    return work;
}

std::string PoolBoundaryFromDifficultyBE(double diff)
{
    if (diff <= 0.0) diff = 1.0;
    cpp_int Q = (cpp_int(1) << 256) - 1;
    cpp_int d = cpp_int(static_cast<unsigned long long>(diff));
    if (d == 0) d = 1;
    cpp_int PB = Q / d;
    std::vector<uint8_t> be(32, 0);
    for (int i = 31; i >= 0; --i)
    {
        be[i] = static_cast<uint8_t>((PB & 0xFF).convert_to<unsigned>());
        PB >>= 8;
    }
    return BytesToHexBE(be);
}
