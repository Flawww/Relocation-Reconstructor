#include <Windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <vector>
#include <unordered_map>
#include <array>
#include <filesystem>
#include <Psapi.h>

#include "reloc_exports_recovery/nlohmann/json.hpp"

using json = nlohmann::json;

uint8_t* make_file_buffer(const char* filename, size_t* len) {
    uint8_t* buf = nullptr;
    try {
        std::fstream file(filename, std::ios::binary | std::ios::in);

        file.seekg(0, std::ios::end);
        size_t size = file.tellg();
        file.seekg(0, std::ios::beg);

        buf = (uint8_t*)malloc(size);
        file.read((char*)buf, size);

        if (len)
            *len = size;

        return buf;
    }
    catch (std::filesystem::filesystem_error & e) {
        printf("%s\n", e.what());
        if (buf)
            free(buf);
    }

    return nullptr;
}

struct export_information {
    std::string module_name;
    std::string export_name;
};

struct relocation_information {
    uintptr_t offset; // offset from start of image buffer to the reloc 
    uintptr_t rva; // offset from start of the image where the reloc points to
};

struct iat_information {
    uintptr_t offset; // offset frrom start of iamge to where the import is stored
    export_information import; // module!export that iat should point to

    uintptr_t real_address;
    bool relative;
};

struct direct_memory_reference {
    uintptr_t offset;
    std::string module_name;
    uintptr_t module_addr;
    uintptr_t rva;
};

#define OEP_OFFSET 0 // <Offset to original entry point goes here>

void init() {
    size_t sz;
    auto buf = make_file_buffer("relocated.dll", &sz);
    printf("Opened file buffer of %X bytes\n", sz);

    std::vector<relocation_information> relocs;
    std::vector<iat_information> iats;
    std::vector<direct_memory_reference> mem_refs;

    std::ifstream f("reloc_info.txt");
    if (!f.good()) {
        printf("Failed opening config file\n");
        return;
    }

    std::stringstream ss;
    ss << f.rdbuf();

    json cfg = json::parse(ss.str(), nullptr, false);
    if (cfg.is_discarded()) {
        printf("Failed parsing config file\n");
        return;
    }

    auto r = cfg["RELOCS"];
    for (auto& it : r) {
        relocation_information info;

        info.offset = it["OFFSET"].get<uintptr_t>();
        info.rva = it["RVA"].get<uintptr_t>();

        //printf("offset %X -> RVA %X\n", info.reloc_address, info.rva);
        relocs.push_back(info);
    }

    auto iat = cfg["IAT"];
    for (auto& it : iat) {
        iat_information info;
        info.offset = it["OFFSET"].get<uintptr_t>();
        info.import.export_name = it["EXPORT"].get<std::string>();
        info.import.module_name = it["MODULE"].get<std::string>();
        info.relative = it["RELATIVE"].get<bool>();

        auto lib = GetModuleHandleA(info.import.module_name.c_str());
        if (!lib) {
            lib = LoadLibraryA(info.import.module_name.c_str());
            if (!lib) {
                printf("%s failed loading\n", info.import.module_name.c_str());
                Sleep(5000);
                return;
            }
        }

        info.real_address = (uintptr_t)GetProcAddress(lib, info.import.export_name.c_str());
        //printf("%s!%s (%X) at offset %X\n", info.import.module_name.c_str(), info.import.export_name.c_str(), info.real_address, info.import_address);
        iats.push_back(info);
    }

    auto memref = cfg["MEMREF"];
    for (auto& it : memref) {
        direct_memory_reference info;
        info.module_name = it["MODULE"].get<std::string>();
        info.offset = it["OFFSET"].get<uintptr_t>();
        info.rva = it["RVA"].get<uintptr_t>();

        info.module_addr = (uintptr_t)GetModuleHandleA(info.module_name.c_str());
    }

    printf("Parsed %i relocations, %i IATs and %i memory references from config file\n", relocs.size(), iats.size(), mem_refs.size());

    uintptr_t binary = (uintptr_t)VirtualAlloc(nullptr, sz, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    // fix up the relocs and IAT
    printf("Patching relocations...\n");
    for (auto& it : relocs) {
        *reinterpret_cast<uintptr_t*>(buf + it.offset) = binary + it.rva;
    }

    printf("Patching IATS...\n");
    for (auto& it : iats) {
        if (it.relative) {
            *reinterpret_cast<uintptr_t*>(buf + it.offset) = (it.real_address) - (binary + it.offset + 4);
        }
        else {
            *reinterpret_cast<uintptr_t*>(buf + it.offset) = it.real_address;
        }

    }

    printf("Patching memory references...\n");
    for (auto& it : mem_refs) {
        *reinterpret_cast<uintptr_t*>(buf + it.offset) = it.module_addr + it.rva;
    }

    // map buffer to addr
    memcpy((void*)(binary), buf, sz);   

    // now manually call the init
    CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)(binary + OEP_OFFSET), nullptr, 0, nullptr);
}
