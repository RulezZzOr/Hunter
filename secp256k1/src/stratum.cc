#include "../include/stratum.h"

#include "../include/conversion.h"
#include "../include/easylogging++.h"
#include "../include/jsmn.h"

#include <chrono>
#include <sstream>
#include <iomanip>
#include <vector>
#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cmath>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <intrin.h>
#pragma comment(lib, "Ws2_32.lib")
typedef SOCKET socket_t;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
typedef int socket_t;
#endif

namespace
{
constexpr uint16_t kDefaultStratumPort = 3333;
constexpr size_t kMaxTokens = 256;

bool TokenEquals(const std::string & json, const jsmntok_t & tok, const char * str)
{
    size_t len = tok.end - tok.start;
    return tok.type == JSMN_STRING && strlen(str) == len
        && json.compare(tok.start, len, str) == 0;
}

std::string TokenToString(const std::string & json, const jsmntok_t & tok)
{
    if (tok.start < 0 || tok.end < 0 || tok.end <= tok.start)
    {
        return std::string();
    }

    return json.substr(tok.start, tok.end - tok.start);
}

int NextTokenIndex(const jsmntok_t * tokens, int count, int index)
{
    if (index < 0 || index >= count) { return count; }

    int next = index + 1;

    if (tokens[index].type == JSMN_ARRAY || tokens[index].type == JSMN_OBJECT)
    {
        int elements = tokens[index].size;
        for (int i = 0; i < elements; ++i)
        {
            next = NextTokenIndex(tokens, count, next);
        }
    }

    return next;
}

void HexToBytes(const std::string & hex, std::vector<uint8_t> & out)
{
    out.clear();
    size_t len = hex.size();
    if (len % 2 != 0) { return; }

    out.reserve(len / 2);

    for (size_t i = 0; i < len; i += 2)
    {
        uint8_t value = (uint8_t)strtol(hex.substr(i, 2).c_str(), nullptr, 16);
        out.push_back(value);
    }
}

std::string BytesToHex(const uint8_t * data, size_t size)
{
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < size; ++i)
    {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}

void DivideFullQ(uint64_t divisor, uint8_t * dest)
{
    if (!divisor) { divisor = 1; }

    const uint64_t Q[4] = { Q0, Q1, Q2, Q3 };
    uint64_t result[4] = { 0, 0, 0, 0 };

#if defined(__SIZEOF_INT128__)
    unsigned __int128 rem = 0;
    for (int i = 3; i >= 0; --i)
    {
        unsigned __int128 cur = (rem << 64) | Q[i];
        result[i] = static_cast<uint64_t>(cur / divisor);
        rem = cur % divisor;
    }
#elif defined(_MSC_VER)
    unsigned long long rem = 0;
    for (int i = 3; i >= 0; --i)
    {
        unsigned long long q = _udiv128(rem, Q[i], divisor, &rem);
        result[i] = q;
    }
#else
    uint64_t rem = 0;
    for (int i = 3; i >= 0; --i)
    {
        unsigned long long high = (static_cast<unsigned long long>(rem) << 32) | (Q[i] >> 32);
        unsigned long long qHigh = high / divisor;
        rem = high % divisor;
        unsigned long long low = (static_cast<unsigned long long>(rem) << 32) | (Q[i] & 0xFFFFFFFFULL);
        unsigned long long qLow = low / divisor;
        rem = low % divisor;
        result[i] = (qHigh << 32) | qLow;
    }
#endif

    memcpy(dest, result, sizeof(result));
}

} // namespace

StratumClient::StratumClient(info_t * infoPtr)
    : info(infoPtr)
    , running(false)
    , sockfd(-1)
    , subscribeId(1)
    , authorizeId(2)
    , nextRequestId(3)
{
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
    if (info)
    {
        user = info->stratumUser;
        password = info->stratumPassword;
        workerName = info->stratumWorker;
        if (workerName.empty())
        {
            workerName = "default";
        }
        if (!user.empty())
        {
            fullUser = user;
            if (!workerName.empty())
            {
                fullUser += ".";
                fullUser += workerName;
            }
        }
        else
        {
            fullUser = workerName;
        }
    }
}

StratumClient::~StratumClient()
{
    stop();
#ifdef _WIN32
    WSACleanup();
#endif
}

void StratumClient::parseUrl()
{
    host.clear();
    port = kDefaultStratumPort;

    if (!info) { return; }

    std::string url = info->stratumUrl;
    if (url.empty()) { return; }

    auto pos = url.find("://");
    if (pos != std::string::npos)
    {
        url = url.substr(pos + 3);
    }

    pos = url.find(':');
    if (pos != std::string::npos)
    {
        host = url.substr(0, pos);
        port = static_cast<uint16_t>(atoi(url.substr(pos + 1).c_str()));
    }
    else
    {
        host = url;
    }

    if (info)
    {
        memset(info->stratumHost, 0, sizeof(info->stratumHost));
        size_t copyLen = host.size();
        if (copyLen >= sizeof(info->stratumHost))
        {
            copyLen = sizeof(info->stratumHost) - 1;
        }
        memcpy(info->stratumHost, host.data(), copyLen);
        info->stratumPort = port;
    }
}

bool StratumClient::start()
{
    if (!info) { return false; }
    parseUrl();
    if (host.empty())
    {
        LOG(ERROR) << "Stratum host is empty";
        return false;
    }

    running = true;
    info->stratumClient = this;
    worker = std::thread(&StratumClient::ioThread, this);
    return true;
}

void StratumClient::stop()
{
    running = false;
    closeSocket();
    if (worker.joinable())
    {
        worker.join();
    }
}

bool StratumClient::connectSocket()
{
    if (sockfd != -1) { return true; }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo * result = nullptr;
    std::string portStr = std::to_string(port);
    int res = getaddrinfo(host.c_str(), portStr.c_str(), &hints, &result);
    if (res != 0)
    {
        LOG(ERROR) << "Failed to resolve stratum host: " << gai_strerror(res);
        return false;
    }

    for (struct addrinfo * rp = result; rp != nullptr; rp = rp->ai_next)
    {
        socket_t s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (s == -1) { continue; }

        if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0)
        {
            sockfd = s;
            freeaddrinfo(result);
            LOG(INFO) << "Connected to stratum " << host << ":" << port;
            return true;
        }
#ifdef _WIN32
        closesocket(s);
#else
        close(s);
#endif
    }

    freeaddrinfo(result);
    LOG(ERROR) << "Unable to connect to stratum server";
    return false;
}

void StratumClient::closeSocket()
{
    if (sockfd != -1)
    {
#ifdef _WIN32
        closesocket(sockfd);
#else
        close(sockfd);
#endif
        sockfd = -1;
    }
}

bool StratumClient::sendRequest(const std::string & payload)
{
    if (sockfd == -1) { return false; }

    std::lock_guard<std::mutex> lock(sendMutex);
    std::string data = payload;
    data.push_back('\n');

    size_t total = 0;
    while (total < data.size())
    {
#ifdef _WIN32
        int sent = send(sockfd, data.c_str() + total, static_cast<int>(data.size() - total), 0);
#else
        ssize_t sent = send(sockfd, data.c_str() + total, data.size() - total, 0);
#endif
        if (sent <= 0)
        {
            LOG(ERROR) << "Failed to send stratum payload";
            return false;
        }
        total += static_cast<size_t>(sent);
    }

    return true;
}

bool StratumClient::sendSubscribe()
{
    std::ostringstream oss;
    oss << "{\"id\":" << subscribeId
        << ",\"method\":\"mining.subscribe\",\"params\":[]}";
    return sendRequest(oss.str());
}

bool StratumClient::sendAuthorize()
{
    std::ostringstream oss;
    oss << "{\"id\":" << authorizeId
        << ",\"method\":\"mining.authorize\",\"params\":[\""
        << fullUser << "\",\"" << password << "\"]}";
    return sendRequest(oss.str());
}

void StratumClient::ioThread()
{
    while (running)
    {
        if (!connectSocket())
        {
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }

        if (!sendSubscribe())
        {
            closeSocket();
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }

        if (!sendAuthorize())
        {
            closeSocket();
            std::this_thread::sleep_for(std::chrono::seconds(3));
            continue;
        }

        while (running)
        {
            std::string message;
            if (!readMessage(message))
            {
                LOG(ERROR) << "Stratum connection lost";
                break;
            }

            if (!message.empty())
            {
                handleMessage(message);
            }
        }

        closeSocket();
        readBuffer.clear();
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

bool StratumClient::readMessage(std::string & out)
{
    out.clear();
    if (sockfd == -1) { return false; }

    static const size_t bufSize = 4096;
    char buf[bufSize];

    while (running)
    {
#ifdef _WIN32
        int received = recv(sockfd, buf, static_cast<int>(bufSize), 0);
#else
        ssize_t received = recv(sockfd, buf, bufSize, 0);
#endif
        if (received <= 0)
        {
            return false;
        }

        readBuffer.append(buf, received);
        size_t pos;
        while ((pos = readBuffer.find('\n')) != std::string::npos)
        {
            out = readBuffer.substr(0, pos);
            readBuffer.erase(0, pos + 1);
            if (!out.empty())
            {
                return true;
            }
        }
    }

    return false;
}

void StratumClient::handleMessage(const std::string & msg)
{
    jsmn_parser parser;
    jsmntok_t tokens[kMaxTokens];
    jsmn_init(&parser);

    int tokCount = jsmn_parse(&parser, msg.c_str(), msg.size(), tokens, kMaxTokens);
    if (tokCount < 0)
    {
        LOG(ERROR) << "Stratum JSON parse error " << tokCount << ": " << msg;
        return;
    }

    bool isNotification = false;
    for (int i = 1; i < tokCount; ++i)
    {
        if (TokenEquals(msg, tokens[i], "method"))
        {
            isNotification = true;
            break;
        }
    }

    if (isNotification)
    {
        LOG(INFO) << "Stratum <- " << msg;
        handleMethod(msg, tokens, tokCount);
    }
    else
    {
        LOG(INFO) << "Stratum <- " << msg;
        handleResult(msg, tokens, tokCount);
    }
}

void StratumClient::handleResult(const std::string & msg, jsmntok_t * tokens, int tokCount)
{
    int messageId = -1;

    for (int i = 1; i < tokCount; ++i)
    {
        if (TokenEquals(msg, tokens[i], "id"))
        {
            const jsmntok_t & idTok = tokens[i + 1];
            messageId = atoi(TokenToString(msg, idTok).c_str());
            break;
        }
    }

    for (int i = 1; i < tokCount; ++i)
    {
        if (!TokenEquals(msg, tokens[i], "result")) { continue; }
        const jsmntok_t & resultTok = tokens[i + 1];

        if (messageId == subscribeId && resultTok.type == JSMN_ARRAY && resultTok.size >= 3)
        {
            int idx = i + 2; // first element in array
            idx = NextTokenIndex(tokens, tokCount, idx); // skip subscriptions array
            std::string ex1Str = TokenToString(msg, tokens[idx]);
            idx = NextTokenIndex(tokens, tokCount, idx);
            std::string ex2LenStr = TokenToString(msg, tokens[idx]);

            if (info)
            {
                std::vector<uint8_t> ex1Bytes;
                HexToBytes(ex1Str, ex1Bytes);
                info->extraNonce1Len = static_cast<int>(ex1Bytes.size());
                if (info->extraNonce1Len > (int)sizeof(info->extraNonce1))
                {
                    info->extraNonce1Len = sizeof(info->extraNonce1);
                }
                if (info->extraNonce1Len > 0)
                {
                    memcpy(info->extraNonce1, ex1Bytes.data(), info->extraNonce1Len);
                }
                info->extraNonce2Size = atoi(ex2LenStr.c_str());
                if (info->extraNonce2Size > (int)sizeof(info->extraNonce2))
                {
                    info->extraNonce2Size = sizeof(info->extraNonce2);
                }
                memset(info->extraNonce2, 0, sizeof(info->extraNonce2));
                info->extraNonce2Counter.store(0);
            }

            LOG(INFO) << "Subscribed, extranonce1=" << ex1Str
                      << " extranonce2_size=" << ex2LenStr;
        }
        else if (messageId == authorizeId)
        {
            std::string authResult = TokenToString(msg, resultTok);
            LOG(INFO) << "Authorize result: " << authResult;
        }
        else if (messageId >= nextRequestId)
        {
            LOG(INFO) << "Share submission response: " << msg;
        }
        break;
    }
}

void StratumClient::updatePoolBoundary(double shareDiff)
{
    if (!info) { return; }

    uint64_t diffInt = (shareDiff <= 0.0)? 1: static_cast<uint64_t>(shareDiff + 0.5);
    if (std::abs(shareDiff - static_cast<double>(diffInt)) > 0.1)
    {
        LOG(WARNING) << "Non-integer share difficulty detected (" << shareDiff
                     << "), rounding to " << diffInt;
    }
    uint8_t tmp[NUM_SIZE_8];
    DivideFullQ(diffInt, tmp);

    info->info_mutex.lock();
    memcpy(info->poolbound, tmp, NUM_SIZE_8);
    info->info_mutex.unlock();
}

void StratumClient::handleMethod(const std::string & msg, jsmntok_t * tokens, int tokCount)
{
    std::string method;
    int paramsIndex = -1;

    for (int i = 1; i < tokCount; ++i)
    {
        if (TokenEquals(msg, tokens[i], "method"))
        {
            method = TokenToString(msg, tokens[i + 1]);
        }
        if (TokenEquals(msg, tokens[i], "params"))
        {
            paramsIndex = i + 1;
        }
    }

    if (method == "mining.set_difficulty" && paramsIndex >= 0)
    {
        const jsmntok_t & paramsTok = tokens[paramsIndex];
        if (paramsTok.type == JSMN_ARRAY && paramsTok.size >= 1)
        {
            const jsmntok_t & diffTok = tokens[paramsIndex + 1];
            double diff = atof(TokenToString(msg, diffTok).c_str());
            LOG(INFO) << "Share difficulty set to " << diff;
            info->shareDifficulty = diff;
            updatePoolBoundary(diff);
        }
    }
    else if (method == "mining.notify" && paramsIndex >= 0)
    {
        const jsmntok_t & paramsTok = tokens[paramsIndex];
        if (paramsTok.type != JSMN_ARRAY || paramsTok.size < 6)
        {
            LOG(ERROR) << "Unexpected notify format: " << msg;
            return;
        }

        std::vector<int> elementIndex;
        elementIndex.reserve(paramsTok.size);
        int idx = paramsIndex + 1;
        for (int e = 0; e < paramsTok.size; ++e)
        {
            elementIndex.push_back(idx);
            idx = NextTokenIndex(tokens, tokCount, idx);
        }

        std::string jobId = TokenToString(msg, tokens[elementIndex[0]]);
        std::string heightStr = (paramsTok.size > 1)
            ? TokenToString(msg, tokens[elementIndex[1]])
            : std::string();
        std::string msgHex = (paramsTok.size > 2)
            ? TokenToString(msg, tokens[elementIndex[2]])
            : std::string();
        std::string versionStr = (paramsTok.size > 5)
            ? TokenToString(msg, tokens[elementIndex[5]])
            : std::string("0");
        std::string boundaryDec = (paramsTok.size > 6)
            ? TokenToString(msg, tokens[elementIndex[6]])
            : std::string();

        info->info_mutex.lock();
        memset(info->stratumJobId, 0, sizeof(info->stratumJobId));
        info->stratumJobIdLen = (jobId.size() >= sizeof(info->stratumJobId))
            ? sizeof(info->stratumJobId) - 1
            : static_cast<int>(jobId.size());
        memcpy(info->stratumJobId, jobId.c_str(), info->stratumJobIdLen);
        info->height = atoi(heightStr.c_str());
        info->version = atoi(versionStr.c_str());

        for (char & c : msgHex) { c = (char)toupper(c); }
        if (msgHex.size() > NUM_SIZE_4)
        {
            msgHex = msgHex.substr(msgHex.size() - NUM_SIZE_4);
        }
        for (char & c : msgHex) { c = (char)toupper(c); }
        if (msgHex.size() > NUM_SIZE_4)
        {
            LOG(WARNING) << "Truncating Stratum msg_hex from " << msgHex.size()
                         << " chars to " << NUM_SIZE_4;
            msgHex = msgHex.substr(msgHex.size() - NUM_SIZE_4);
        }
        HexStrToBigEndian(msgHex.c_str(), msgHex.size(), info->mes, NUM_SIZE_8);

        if (!boundaryDec.empty())
        {
            char buf[NUM_SIZE_4 + 1];
            DecStrToHexStrOf64(boundaryDec.c_str(), boundaryDec.size(), buf);
            HexStrToLittleEndian(buf, NUM_SIZE_4, info->bound, NUM_SIZE_8);
        }

        if (info->shareDifficulty > 0.0)
        {
            updatePoolBoundary(info->shareDifficulty);
        }
        else
        {
            memcpy(info->poolbound, info->bound, NUM_SIZE_8);
        }

        info->extraNonce2Counter.store(0);

        info->info_mutex.unlock();

        ++(info->blockId);
        LOG(INFO) << "Received new stratum job " << jobId;
    }
    else if (method == "mining.notify" && paramsIndex < 0)
    {
        LOG(ERROR) << "mining.notify without params";
    }
}

bool StratumClient::submitShare(const MinerShare & share)
{
    if (sockfd == -1 || !info) { return false; }

    int requestId = nextRequestId.fetch_add(1);

    char nonceBuf[NONCE_SIZE_4 + 1];
    LittleEndianToHexStr(reinterpret_cast<const uint8_t *>(&share.nonce), NONCE_SIZE_8, nonceBuf);
    std::string nonceHex(nonceBuf);

    std::string ex2Hex;
    int ex2Size = share.extraNonce2Size;
    if (ex2Size <= 0)
    {
        ex2Size = info->extraNonce2Size;
    }

    if (ex2Size > 0)
    {
        if (share.extraNonce2Size > 0)
        {
            ex2Hex = BytesToHex(share.extraNonce2, share.extraNonce2Size);
        }
        else if (info->extraNonce2Size > 0)
        {
            ex2Hex = BytesToHex(info->extraNonce2, info->extraNonce2Size);
        }
        if (ex2Hex.empty())
        {
            ex2Hex.assign(static_cast<size_t>(ex2Size) * 2, '0');
        }
    }

    std::string jobIdStr;
    if (share.jobIdLen > 0)
    {
        jobIdStr.assign(share.jobId, share.jobIdLen);
    }
    else
    {
        jobIdStr = info->stratumJobId;
    }

    std::ostringstream oss;
    oss << "{\"id\":" << requestId
        << ",\"method\":\"mining.submit\",\"params\":[\""
        << fullUser << "\",\"" << jobIdStr << "\",\"" << ex2Hex
        << "\",\"00000000\",\"" << nonceHex << "\"]}";

    LOG(INFO) << "Submitting share nonce=" << nonceHex;
    return sendRequest(oss.str());
}
