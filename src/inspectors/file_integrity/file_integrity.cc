#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "file_integrity.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono> 

#include "framework/inspector.h"
#include "framework/module.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "utils/util.h"

#include "hash/hash_key_operations.h"

#include <openssl/sha.h>

#ifdef _WIN32
#include <windows.h>
#include <fileapi.h>
#else
#include <unistd.h>
#include <sys/stat.h>
#endif

using namespace snort;

FileIntegrity::FileIntegrity() : Inspector() 
{
    baseline_file = "file_integrity_baseline.txt";
    check_interval = 60;
    alert_on_modification = true;
    alert_on_addition = true;
    alert_on_deletion = true;
}

// destructor for object graceful shutdown
FileIntegrity::~FileIntegrity()
{
    running = false;
    if (worker.joinable())
        worker.join();

    save_baseline();
}


void FileIntegrity::configure(const std::vector<std::string>& paths,
                              const std::string& baseline,
                              unsigned interval,
                              bool mod, bool add, bool del)
{
    monitored_paths = paths;
    baseline_file = baseline;
    check_interval = interval;
    alert_on_modification = mod;
    alert_on_addition = add;
    alert_on_deletion = del;
}



void FileIntegrity::show(const SnortConfig*) const
{
    ConfigLogger::log_value("baseline_file", baseline_file.c_str());
    ConfigLogger::log_value("check_interval", check_interval);
    ConfigLogger::log_flag("alert_on_modification", alert_on_modification);
    ConfigLogger::log_flag("alert_on_addition", alert_on_addition);
    ConfigLogger::log_flag("alert_on_deletion", alert_on_deletion);
    
    for (const auto& path : monitored_paths)
    {
        ConfigLogger::log_value("monitored_path", path.c_str());
    }
}


// Opens file, Reads file in 8KB chunks, Updates SHA-256 context with each chunk
std::string FileIntegrity::compute_sha256(const std::string& file_path)
{
#ifdef _WIN32
    HANDLE hFile = CreateFileA(file_path.c_str(), GENERIC_READ, FILE_SHARE_READ, 
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
        return "";
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    const size_t BUFFER_SIZE = 8192;
    char buffer[BUFFER_SIZE];
    DWORD bytesRead = 0;
    
    while (ReadFile(hFile, buffer, BUFFER_SIZE, &bytesRead, NULL) && bytesRead > 0)
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    
    CloseHandle(hFile);
#else
    FILE* file = fopen(file_path.c_str(), "rb");
    if (!file)
        return "";
    
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    
    const size_t BUFFER_SIZE = 8192;
    unsigned char buffer[BUFFER_SIZE];
    size_t bytesRead = 0;
    
    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0)
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    
    fclose(file);
#endif

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    
    return ss.str();
}


// reads a baseline file that contains file paths and their expected SHA-256 hashes
void FileIntegrity::load_baseline()
{
    std::lock_guard<std::mutex> lock(hash_mutex);
    std::ifstream file(baseline_file);
    
    if (!file.is_open())
    {
        LogMessage("No baseline file found. Creating new baseline.\n");
        return;
    }
    
    std::string line;
    while (std::getline(file, line))
    {
        size_t pos = line.find('|');
        if (pos != std::string::npos)
        {
            std::string file_path = line.substr(0, pos);
            std::string hash = line.substr(pos + 1);
            file_hashes[file_path] = hash;
        }
    }
    
    LogMessage("Loaded baseline with %lu files\n", file_hashes.size());
}

void FileIntegrity::save_baseline()
{
    std::lock_guard<std::mutex> lock(hash_mutex);
    std::ofstream file(baseline_file);
    
    if (!file.is_open())
    {
        ErrorMessage("Cannot save baseline file: %s\n", baseline_file.c_str());
        return;
    }
    
    for (const auto& entry : file_hashes)
    {
        file << entry.first << "|" << entry.second << "\n";
    }
    
    LogMessage("Saved baseline with %lu files\n", file_hashes.size());
}

void FileIntegrity::monitor_files()
{
    std::unordered_map<std::string, std::string> current_hashes;
    
    // Compute hashes for all monitored files
    for (const auto& path : monitored_paths)
    {
#ifdef _WIN32
        // Windows directory monitoring
        if (path.find('*') != std::string::npos || path.back() == '\\')
        {
            WIN32_FIND_DATAA findFileData;
            HANDLE hFind = FindFirstFileA(path.c_str(), &findFileData);
            
            if (hFind != INVALID_HANDLE_VALUE)
            {
                do
                {
                    if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                    {
                        std::string full_path = path.substr(0, path.find('*')) + findFileData.cFileName;
                        std::string hash = compute_sha256(full_path);
                        if (!hash.empty())
                        {
                            current_hashes[full_path] = hash;
                        }
                    }
                } while (FindNextFileA(hFind, &findFileData));
                FindClose(hFind);
            }
        }
        else
#endif
        {
            std::string hash = compute_sha256(path);
            if (!hash.empty())
            {
                current_hashes[path] = hash;
            }
        }
    }
    
    std::lock_guard<std::mutex> lock(hash_mutex);
    
    for (const auto& old_entry : file_hashes)
    {
        const std::string& file_path = old_entry.first;
        const std::string& old_hash = old_entry.second;
        
        auto new_it = current_hashes.find(file_path);

        // Files that exist in old hashes but not in current hashes
        if (new_it == current_hashes.end())
        {
            if (alert_on_deletion)
            {
                LogMessage("ALERT: File deleted - %s\n", file_path.c_str());
            }
        }
        else if (new_it->second != old_hash)
        {
            if (alert_on_modification)
            {
                LogMessage("ALERT: File modified - %s\n", file_path.c_str());
                LogMessage("  Old hash: %s\n", old_hash.c_str());
                LogMessage("  New hash: %s\n", new_it->second.c_str());
            }
        }
    }
    
    for (const auto& new_entry : current_hashes)
    {
        const std::string& file_path = new_entry.first;
        
        if (file_hashes.find(file_path) == file_hashes.end())
        {
            if (alert_on_addition)
            {
                LogMessage("ALERT: New file detected - %s\n", file_path.c_str());
                LogMessage("  Hash: %s\n", new_entry.second.c_str());
            }
        }
    }
    
    // updates the stored file hashes with current state
    file_hashes = std::move(current_hashes);
}

void FileIntegrity::check_integrity()
{
    monitor_files();
}

// background watchdog that continuously monitors file integrity at regular intervals
void FileIntegrity::tinit()
{
    load_baseline();
    running = true;
    worker = std::thread([this]{
        LogMessage("[file_integrity] monitor loop started\n");
        while (running) {
            monitor_files();
            for (unsigned i=0; running && i<check_interval; ++i)
                std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
}

void FileIntegrity::tterm()
{
    running = false;
    if (worker.joinable()) worker.join();
    save_baseline();
}

