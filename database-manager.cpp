#include <iostream>
#include <string>
#include <unordered_map>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <vector>
#include <stdexcept>
#include <cstdint>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;


namespace Crypto {
    using Byte = uint8_t;
    constexpr size_t AES256_KEY_SIZE = 32;
    constexpr size_t AES_BLOCK_SIZE = 16;

    std::vector<Byte> pkcs7Pad(const std::vector<Byte>& in, size_t blockSize) {
        std::vector<Byte> out = in;
        Byte padLen = static_cast<Byte>(blockSize - (out.size() % blockSize));
        for (size_t i = 0; i < padLen; i++) out.push_back(padLen);
        return out;
    }
    std::vector<Byte> pkcs7Unpad(const std::vector<Byte>& in) {
        if (in.empty()) throw std::runtime_error("empty buffer");
        Byte padLen = in.back();
        if (padLen == 0 || padLen > in.size()) throw std::runtime_error("bad padding");
        return { in.begin(), in.end() - padLen };
    }
    void cbcXor(std::vector<Byte>& buf, const std::vector<Byte>& iv, bool encrypt) {
        std::vector<Byte> prev = iv;
        for (size_t i = 0; i < buf.size(); i += AES_BLOCK_SIZE) {
            for (size_t j = 0; j < AES_BLOCK_SIZE; j++) buf[i + j] ^= prev[j];
            prev.assign(buf.begin() + i, buf.begin() + i + AES_BLOCK_SIZE);
        }
    }
    std::vector<Byte> passwordToKey(const std::string& pass, const std::vector<Byte>& salt) {
        std::vector<Byte> key(AES256_KEY_SIZE, 0);
        std::vector<Byte> buf;
        for (auto ch : pass) buf.push_back(static_cast<Byte>(ch));
        buf.insert(buf.end(), salt.begin(), salt.end());
        for (int r = 0; r < 1000; r++) {
            for (size_t i = 0; i < buf.size(); i++) key[i % AES256_KEY_SIZE] ^= buf[i];
        }
        return key;
    }
    void aesBlockEncrypt(std::vector<Byte>& /*block*/, const std::vector<Byte>& /*key*/) {}
    void aesBlockDecrypt(std::vector<Byte>& /*block*/, const std::vector<Byte>& /*key*/) {}

    std::vector<Byte> aes256cbcEncrypt(const std::vector<Byte>& plain, const std::vector<Byte>& key, const std::vector<Byte>& iv)
    {
        auto padded = pkcs7Pad(plain, AES_BLOCK_SIZE);
        cbcXor(padded, iv, true);
        for (size_t i = 0; i < padded.size(); i += AES_BLOCK_SIZE) {
            std::vector<Byte> blk(padded.begin() + i, padded.begin() + i + AES_BLOCK_SIZE);
            aesBlockEncrypt(blk, key);
            std::copy(blk.begin(), blk.end(), padded.begin() + i);
        }
        return padded;
    }
    std::vector<Byte> aes256cbcDecrypt(const std::vector<Byte>& cipher, const std::vector<Byte>& key, const std::vector<Byte>& iv)
    {
        std::vector<Byte> data = cipher;
        for (size_t i = 0; i < data.size(); i += AES_BLOCK_SIZE) {
            std::vector<Byte> blk(data.begin() + i, data.begin() + i + AES_BLOCK_SIZE);
            aesBlockDecrypt(blk, key);
            std::copy(blk.begin(), blk.end(), data.begin() + i);
        }
        cbcXor(data, iv, false);
        return pkcs7Unpad(data);
    }

    std::vector<Byte> str2bytes(const std::string& s) { return { s.begin(),s.end() }; }
    std::string bytes2str(const std::vector<Byte>& b) { return { b.begin(),b.end() }; }
}


std::string inputPassword(const std::string& prompt)
{
    std::cout << prompt;
    std::string pw;
#ifdef _WIN32
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hIn, &mode);
    SetConsoleMode(hIn, mode & ~ENABLE_ECHO_INPUT);
    std::getline(std::cin, pw);
    SetConsoleMode(hIn, mode);
#else
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    std::getline(std::cin, pw);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    std::cout << "\n";
    return pw;
}


class Database {
private:
    std::unordered_map<int, std::string> m_store;
    std::string m_filePath;
    bool m_passwordProtected{ false };
    std::vector<uint8_t> m_salt;
    std::vector<uint8_t> m_iv;
    std::vector<uint8_t> m_aesKey;
    static constexpr uint32_t DB_MAGIC = 0xAA55BB77;

    template<typename T>
    bool writeBin(std::ofstream& os, const T& val) {
        os.write(reinterpret_cast<const char*>(&val), sizeof(T));
        return os.good();
    }
    template<typename T>
    bool readBin(std::ifstream& is, T& val) {
        is.read(reinterpret_cast<char*>(&val), sizeof(T));
        return is.good();
    }
public:
    Database() {
        m_salt.resize(16, 0x33);
        m_iv.resize(16, 0x77);
    }

    void setFilePath(std::string fp) {
        m_filePath = std::move(fp);
        auto p = fs::path(m_filePath).parent_path();
        if (!p.empty() && !fs::exists(p)) fs::create_directories(p);
    }
    std::string getFilePath() const { return m_filePath; }

    bool setPassword(const std::string& pass) {
        try {
            m_aesKey = Crypto::passwordToKey(pass, m_salt);
            m_passwordProtected = true;
            return saveToDisk();
        }
        catch (...) { return false; }
    }
    bool clearPassword() {
        m_passwordProtected = false;
        m_aesKey.clear();
        return saveToDisk();
    }
    bool verifyPassword(const std::string& pass) const {
        if (!m_passwordProtected) return true;
        auto testKey = Crypto::passwordToKey(pass, m_salt);
        return testKey == m_aesKey;
    }
    bool isPasswordProtected() const { return m_passwordProtected; }

    bool loadFromDisk() {
        if (m_filePath.empty()) throw std::runtime_error("no file path");
        if (!fs::exists(m_filePath)) {
            m_store.clear();
            m_passwordProtected = false;
            m_aesKey.clear();
            return true;
        }
        std::ifstream fi(m_filePath, std::ios::binary);
        if (!fi) throw std::runtime_error("cannot open file");
        uint32_t magic;
        if (!readBin(fi, magic) || magic != DB_MAGIC) throw std::runtime_error("invalid database file");
        uint8_t pwFlag;
        readBin(fi, pwFlag);
        m_passwordProtected = (pwFlag != 0);
        uint32_t recCnt;
        readBin(fi, recCnt);
        m_store.clear();
        for (uint32_t i = 0; i < recCnt; i++) {
            int k; uint32_t len;
            readBin(fi, k);
            readBin(fi, len);
            std::string v(len, 0);
            fi.read(&v[0], len);
            m_store[k] = v;
        }
        fi.close();
        return true;
    }
    bool saveToDisk() {
        if (m_filePath.empty()) throw std::runtime_error("no file path");
        std::ofstream fo(m_filePath, std::ios::binary);
        if (!fo) throw std::runtime_error("write failed");
        writeBin(fo, DB_MAGIC);
        writeBin(fo, static_cast<uint8_t>(m_passwordProtected ? 1 : 0));
        uint32_t recCnt = static_cast<uint32_t>(m_store.size());
        writeBin(fo, recCnt);
        for (auto& p : m_store) {
            writeBin(fo, p.first);
            uint32_t len = static_cast<uint32_t>(p.second.size());
            writeBin(fo, len);
            fo.write(p.second.data(), len);
        }
        fo.close();
        return true;
    }

    bool add(int key, const std::string& val) {
        try {
            m_store[key] = val;
            return saveToDisk();
        }
        catch (...) { return false; }
    }
    bool del(int key) {
        auto it = m_store.find(key);
        if (it == m_store.end()) return false;
        m_store.erase(it);
        return saveToDisk();
    }
    std::string get(int key) const {
        auto it = m_store.find(key);
        if (it == m_store.end()) return "";
        return it->second;
    }
    void findValue(const std::string& val) const {
        bool found = false;
        for (auto& p : m_store) {
            if (p.second == val) {
                std::cout << "Found: key=" << p.first << " value=\"" << p.second << "\"\n";
                found = true;
            }
        }
        if (!found) std::cout << "Not found.\n";
    }
    void listAllRecords() const
    {
        std::cout << "\nRecord list:\n";
        if (m_store.empty())
        {
            std::cout << "(empty database)\n";
        }
        else
        {
            for (const auto& pair : m_store)
            {
                std::cout << "Key: " << pair.first << " | Value: " << pair.second << "\n";
            }
        }
        std::cout << "Total records: " << m_store.size() << "\n\n";
    }

    void close() {
        m_filePath.clear();
        m_store.clear();
        m_passwordProtected = false;
        m_aesKey.clear();
    }
};


void printGlobalHelp() {
    std::cout << "\n==== Global Commands (before open database) ====\n";
    std::cout << "create <filepath>      : create new database file (suggest suffix .data)\n";
    std::cout << "remove <filepath>       : physically delete *.data database file only\n";
    std::cout << "work <filepath>        : open existing database file\n";
    std::cout << "help                   : show this help\n";
    std::cout << "exit                   : quit program\n\n";
}
void printDatabaseHelp() {
    std::cout << "\n==== Database Internal Commands ====\n";
    std::cout << "add <key> <value>      : insert/update record\n";
    std::cout << "get <key>              : get record by key\n";
    std::cout << "del <key>              : delete record by key\n";
    std::cout << "find <value>           : search records by value\n";
    std::cout << "list                   : list all records in database\n";
    std::cout << "setpw                  : set database password\n";
    std::cout << "clearpw                : remove database password\n";
    std::cout << "close                  : close database, back to global mode\n";
    std::cout << "help                   : show this help\n";
    std::cout << "exit                   : quit program\n\n";
}

int runInteractive(Database& db) {
    printGlobalHelp();
    std::string line;
    bool opened = false;
    while (true) {
        if (opened) std::cout << db.getFilePath() << "> ";
        else std::cout << "database> ";
        if (!std::getline(std::cin, line)) break;
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        if (cmd == "exit") {
            std::cout << "Exiting database.\n";
            break;
        }
        if (!opened)
        {
            if (cmd == "help") printGlobalHelp();
            else if (cmd == "create")
            {
                iss >> std::ws;
                std::string path;
                std::getline(iss, path);
                if (path.empty()) { std::cout << "Usage: create <filepath>\n"; continue; }
                try {
                    db.setFilePath(path);
                    if (fs::exists(path)) std::cout << "[WARNING] File already exists.\n";
                    else {
                        db.saveToDisk();
                        std::cout << "[OK] Created: " << path << "\n";
                    }
                    db.close();
                }
                catch (std::exception& e) {
                    std::cerr << "[ERROR] " << e.what() << "\n";
                    db.close();
                }
            }
            else if (cmd == "remove")
            {
                iss >> std::ws;
                std::string path;
                std::getline(iss, path);
                if (path.empty()) { std::cout << "Usage: remove <filepath>\n"; continue; }

                
                if (path.size() < 5 || path.substr(path.size() - 5) != ".data")
                {
                    std::cout << "[ERROR] Only files with .data suffix can be removed.\n";
                    continue;
                }
                
                if (opened && fs::equivalent(path, db.getFilePath()))
                {
                    std::cout << "[ERROR] File is currently opened, please close database first.\n";
                    continue;
                }

                try {
                    if (fs::exists(path)) {
                        fs::remove(path);
                        std::cout << "[OK] Removed: " << path << "\n";
                    }
                    else std::cout << "[INFO] File not exist.\n";
                }
                catch (std::exception& e) {
                    std::cerr << "[ERROR] Remove failed: " << e.what() << "\n";
                }
            }
            else if (cmd == "work")
            {
                iss >> std::ws;
                std::string path;
                std::getline(iss, path);
                if (path.empty()) { std::cout << "Usage: work <filepath>\n"; continue; }
                try {
                    db.setFilePath(path);
                    std::cout << "[INFO] Loading: " << path << "\n";
                    db.loadFromDisk();
                    if (db.isPasswordProtected()) {
                        bool ok = false;
                        for (int i = 0; i < 3; i++) {
                            auto pw = inputPassword("Database password: ");
                            if (db.verifyPassword(pw)) { ok = true; db.loadFromDisk(); break; }
                            std::cout << "Wrong password, remain " << (2 - i) << "\n";
                        }
                        if (!ok) {
                            std::cout << "Too many wrong password.\n";
                            db.close();
                            continue;
                        }
                    }
                    opened = true;
                    std::cout << "[OK] Database opened.\n";
                    printDatabaseHelp();
                }
                catch (std::exception& e) {
                    std::cerr << "[ERROR] " << e.what() << "\n";
                    db.close();
                }
            }
            else {
                std::cout << "Error: unknown command, type help.\n";
            }
        }
        else
        {
            if (cmd == "help") printDatabaseHelp();
            else if (cmd == "close") {
                db.close();
                opened = false;
                std::cout << "[OK] Closed, return global mode.\n";
                printGlobalHelp();
            }
            else if (cmd == "add") {
                int k; std::string v;
                if (!(iss >> k)) { std::cout << "Usage: add <key> <value>\n"; continue; }
                iss >> std::ws;
                std::getline(iss, v);
                if (db.add(k, v)) std::cout << "OK\n";
                else std::cout << "Failed add.\n";
            }
            else if (cmd == "get") {
                int k;
                if (!(iss >> k)) { std::cout << "Usage: get <key>\n"; continue; }
                auto res = db.get(k);
                if (res.empty()) std::cout << "(empty / not exists)\n";
                else std::cout << "Result: \"" << res << "\"\n";
            }
            else if (cmd == "del") {
                int k;
                if (!(iss >> k)) { std::cout << "Usage: del <key>\n"; continue; }
                if (db.del(k)) std::cout << "OK\n";
                else std::cout << "Key does not exist.\n";
            }
            else if (cmd == "find") {
                iss >> std::ws;
                std::string val;
                std::getline(iss, val);
                if (val.empty()) { std::cout << "Usage: find <value>\n"; continue; }
                db.findValue(val);
            }
            else if (cmd == "list")
            {
                db.listAllRecords();
            }
            else if (cmd == "setpw") {
                auto p1 = inputPassword("Enter new password: ");
                auto p2 = inputPassword("Confirm password: ");
                if (p1 != p2) { std::cout << "Password mismatch.\n"; continue; }
                if (db.setPassword(p1)) std::cout << "Password set ok.\n";
                else std::cout << "Set password failed.\n";
            }
            else if (cmd == "clearpw") {
                std::cout << "Warning: remove password? (y/N):";
                std::string c; std::getline(std::cin, c);
                if (c == "y" || c == "Y") {
                    if (db.clearPassword()) std::cout << "Password cleared.\n";
                    else std::cout << "Clear password failed.\n";
                }
            }
            else {
                std::cout << "Unknown command, type help.\n";
            }
        }
    }
    return 0;
}

int runArgMode(int argc, char* argv[], Database& db)
{
    if (argc < 3) return -1;
    std::string fp = argv[1];
    std::string subcmd = argv[2];
    
    if (fp.size() < 5 || fp.substr(fp.size() - 5) != ".data")
    {
        std::cerr << "[ERROR] Only files with .data suffix supported.\n";
        return 1;
    }
    db.setFilePath(fp);
    if (!fs::exists(fp)) { std::cerr << "File not found\n"; return 1; }
    db.loadFromDisk();
    if (db.isPasswordProtected()) {
        bool ok = false;
        for (int i = 0; i < 3; i++) {
            auto pw = inputPassword("Password: ");
            if (db.verifyPassword(pw)) { ok = true; db.loadFromDisk(); break; }
            std::cout << "Wrong password\n";
        }
        if (!ok) return 2;
    }
    if (subcmd == "add" && argc >= 5) {
        int k = std::stoi(argv[3]);
        std::string v = argv[4];
        std::cout << (db.add(k, v) ? "OK" : "FAIL") << "\n";
    }
    else if (subcmd == "get" && argc >= 4) {
        int k = std::stoi(argv[3]);
        auto r = db.get(k);
        std::cout << r << "\n";
    }
    else if (subcmd == "del" && argc >= 4) {
        int k = std::stoi(argv[3]);
        std::cout << (db.del(k) ? "OK" : "FAIL") << "\n";
    }
    else if (subcmd == "find" && argc >= 4) {
        std::string v = argv[3];
        db.findValue(v);
    }
    else if (subcmd == "list") {
        db.listAllRecords();
    }
    return 0;
}

int main(int argc, char* argv[])
{
    try {
        Database db;
        if (argc >= 2) return runArgMode(argc, argv, db);
        else return runInteractive(db);
    }
    catch (std::exception& e) {
        std::cerr << "[EXCEPTION] " << e.what() << "\n";
        return 1;
    }
}
