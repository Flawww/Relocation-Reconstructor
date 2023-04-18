#include "pch.h"
#include "module_relocation_information.h"

#define ASSERT(cond, msg, ...) if(!cond) {printf(msg, __VA_ARGS__); return; }
#define ASSERT_RET(cond, ret, msg, ...) if(!cond) {printf(msg, __VA_ARGS__); ret; }

uint8_t* make_file_buffer(const char* filename, size_t * len) {
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

module_relocation_information::~module_relocation_information() {
    if (m_image_buf)
        free(m_image_buf);
}

bool module_relocation_information::init(std::string folder_path, module_section_information* section_info) {
    m_image_buf = make_file_buffer((folder_path + "/mem.bin").c_str(), &m_image_size);
    ASSERT_RET(m_image_buf, return false, "Failed opening binary file %s\n", (folder_path + "/mem.bin").c_str());

    std::ifstream exports_file(folder_path + "/exports.txt");
    ASSERT_RET(exports_file.good(), return false, "Failed opened exports file %s\n", (folder_path + "/exports.txt").c_str());

    std::stringstream ss;
    ss << exports_file.rdbuf();

    json cfg = json::parse(ss.str(), nullptr, false);
    ASSERT_RET(!cfg.is_discarded(), return false, "Failed parsing exports file\n");

    export_information info;

    auto mod_kvp = cfg.get<json::object_t>();
    for (auto& mod : mod_kvp) {
        info.module_name = mod.first;

        // add the module 
        mapped_module_information module_info;
        module_info.module_name = mod.first;
        module_info.base_address = mod.second["BASEADDR"];
        module_info.size_of_image = mod.second["SIZEOFIMAGE"];
        m_mapped_modules.push_back(module_info);

        // add reverse lookups for exports
        auto exports_kvp = mod.second.get<json::object_t>();
        for (auto& ex : exports_kvp) {
            info.export_name = ex.first;
            m_reverese_export_map.emplace(ex.second.get<uintptr_t>(), info);
        }
    }

    printf("Created reverse export lookup table from (%s/exports.txt) for %i items\n\n", folder_path.c_str(), m_reverese_export_map.size());

    std::string start_addr, end_addr;

    printf("Enter module base/load address (BASE 16): ");
    std::getline(std::cin, start_addr);
#ifdef _WIN64
    m_sections.base_address = std::stoull(start_addr, nullptr, 16);
#else
    m_sections.base_address = std::stoul(start_addr, nullptr, 16);
#endif
    

    //m_sections.sections[TEXT].start_offset = section_info->sections[TEXT].start_offset;
    //m_sections.sections[TEXT].end_offset = section_info->sections[TEXT].end_offset;

    //m_sections.sections[RDATA].start_offset = section_info->sections[RDATA].start_offset;
    //m_sections.sections[RDATA].end_offset = section_info->sections[RDATA].end_offset;

    //m_sections.sections[DATA].start_offset = section_info->sections[DATA].start_offset;
    //m_sections.sections[DATA].end_offset = section_info->sections[DATA].end_offset;

    return true;
}

uintptr_t module_relocation_information::calculate_rva(uintptr_t addr) {
    return addr - m_sections.base_address;
}

bool module_relocation_information::module_contains_address(uintptr_t addr) {
    if (addr < m_sections.base_address)
        return false;

    if (addr > (m_sections.base_address + m_image_size))
        return false;

    return true;
}

export_information* module_relocation_information::get_export_for_address(uintptr_t addr) {
    auto it = &m_reverese_export_map.find(addr);
    if (*it == m_reverese_export_map.end())
        return nullptr; // didnt find it
    
    return &((*it)->second);
}

direct_memory_reference module_relocation_information::get_direct_memory_reference(uintptr_t addr) {
    direct_memory_reference out;
    out.valid = false;

    for (auto& it : m_mapped_modules) {
        if (addr < it.base_address || addr > (it.base_address + it.size_of_image))
            continue;

        // found it
        out.module_name = it.module_name;
        out.rva = addr - it.base_address;
        out.valid = true;
    }

    return out;
}