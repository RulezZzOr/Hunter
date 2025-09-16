#ifndef STRATUM_H
#define STRATUM_H

#include "definitions.h"
#include "queue.h"
#include <atomic>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <unordered_map>

class StratumClient
{
public:
    StratumClient(info_t * info);
    ~StratumClient();

    bool start();
    void stop();
    bool submitShare(const MinerShare & share);

private:
    struct PendingShare
    {
        int gpuId;
        double difficulty;
        bool isBlockCandidate;
    };

    bool connectSocket();
    void closeSocket();
    bool sendRequest(const std::string & payload);
    bool sendSubscribe();
    bool sendAuthorize();
    void ioThread();
    bool readMessage(std::string & out);
    void handleMessage(const std::string & msg);
    void handleResult(const std::string & msg, jsmntok_t * tokens, int tokCount);
    void handleMethod(const std::string & msg, jsmntok_t * tokens, int tokCount);
    void updatePoolBoundary(double shareDiff);
    void parseUrl();

    info_t * info;
    std::thread worker;
    std::atomic<bool> running;
    std::mutex sendMutex;
    int sockfd;
    int subscribeId;
    int authorizeId;
    std::atomic<int> nextRequestId;
    std::string host;
    uint16_t port;
    std::string user;
    std::string password;
    std::string workerName;
    std::string fullUser;
    std::string readBuffer;
    std::mutex pendingMutex;
    std::unordered_map<int, PendingShare> pendingShares;
};

#endif // STRATUM_H
