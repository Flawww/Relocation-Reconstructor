#pragma once
#include "pch.h"
#include "module_relocation_information.h"

struct relocation_information {
	uintptr_t reloc_address; // offset from start of image buffer to the reloc 
	uintptr_t rva; // offset from start of the image where the reloc points to
};

struct iat_information {
	uintptr_t import_address; // offset frrom start of iamge to where the import is stored
	export_information import; // module!export that iat should point to
};

class relocator {
public:
	relocator();
	~relocator();

	void start();

private:
	module_relocation_information* get_module(std::string folder_path);
	void scan_dumps();
	void scan_section(sections_t section, uintptr_t pad = 1);

	module_section_information m_sections;

	std::vector<relocation_information> m_relocs;
	std::vector<iat_information> m_iats;
	std::vector<module_relocation_information*> m_modules;
};

/*
	printf("Enter start offset of .text: ");
	std::getline(std::cin, start_addr);
	printf("Enter end offset of .text: ");
	std::getline(std::cin, end_addr);

	m_sections.sections[TEXT].start_offset = std::stoul(start_addr, nullptr, 16);
	m_sections.sections[TEXT].end_offset = std::stoul(end_addr, nullptr, 16);

	printf("Enter start offset of .rdata (BASE 16): ");
	std::getline(std::cin, start_addr);
	printf("Enter end offset of .rdata: ");
	std::getline(std::cin, end_addr);

	m_sections.sections[RDATA].start_offset = std::stoul(start_addr, nullptr, 16);
	m_sections.sections[RDATA].end_offset = std::stoul(end_addr, nullptr, 16);

	printf("Enter start offset of .data (BASE 16): ");
	std::getline(std::cin, start_addr);
	printf("Enter end offset of .data: ");
	std::getline(std::cin, end_addr);

	m_sections.sections[DATA].start_offset = std::stoul(start_addr, nullptr, 16);
	m_sections.sections[DATA].end_offset = std::stoul(end_addr, nullptr, 16);
*/