#pragma once
#include "pch.h"

enum sections_t {
	TEXT,
	RDATA,
	DATA,

	NUM_SECTIONS
};

struct export_information {
	std::string module_name;
	std::string export_name;
};

struct module_section_information {
	struct section_info {
		uintptr_t start_offset;
		uintptr_t end_offset;
	};

	uintptr_t base_address;
	section_info sections[NUM_SECTIONS];
};

class module_relocation_information {
public:
	module_relocation_information() { m_image_buf = nullptr; m_reverese_export_map.clear(); };
	~module_relocation_information();
	bool init(std::string folder_path, module_section_information* section_info);

	bool module_contains_address(uintptr_t addr);
	uintptr_t calculate_rva(uintptr_t addr);
	export_information* get_export_for_address(uintptr_t addr);

	size_t m_image_size;
	uint8_t* m_image_buf;

	module_section_information m_sections;
	std::unordered_map<uintptr_t, export_information> m_reverese_export_map;
};