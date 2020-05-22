#include "pch.h"
#include "relocator.h"

relocator::relocator() {
	m_relocs.clear();
	m_iats.clear();
	m_memory_references.clear();
	m_modules.clear();
}

relocator::~relocator() {
	for (auto it : m_modules)
		delete it;
}

void relocator::start() {
	std::string in, start_addr, end_addr;

	while (true) {
		printf("Enter folder path for dump %i to load: ", m_modules.size() + 1);
		std::getline(std::cin, in);

		auto mod = get_module(in);
		if (mod) {
			m_modules.push_back(mod);
		}

		if (m_modules.size() >= 2) {
			bool stop = false;
			while (true) {
				printf("\nAdd additional dump? (y/n): ");
				std::getline(std::cin, in);
				if (in.length() != 1)
					continue;

				in[0] = std::tolower(in[0]);
				if (!in.compare("y")) {
					stop = false;
					break;
				}
				else if (!in.compare("n")) {
					stop = true;
					break;
				}
			}

			if (stop)
				break;
		}

		printf("\n");
	}

	// now start the comparison
	scan_dumps();

	auto mod = m_modules.at(0);

	size_t reloc_section_size, import_section_size;
	auto reloc_section = create_reloc_section(&reloc_section_size);

	uintptr_t reloc_start = mod->m_image_size;
	uintptr_t reloc_end = reloc_start + reloc_section_size;
	uintptr_t import_start = reloc_end;

	auto import_section = create_import_section(&import_section_size, import_start);

	uintptr_t import_end = import_start + import_section_size;

	printf("\nCreating reloc section at %X - %X\nCreating import section at %X - %X\n", reloc_start, reloc_end, import_start, import_end);

	auto file_buf = (uint8_t*)malloc(import_end);
	if (!reloc_section || !import_section || !file_buf)
		return;

	memcpy(file_buf, mod->m_image_buf, mod->m_image_size);
	memcpy(file_buf + reloc_start, reloc_section, reloc_section_size);
	memcpy(file_buf + import_start, import_section, import_section_size);

	FILE* out_file;
	fopen_s(&out_file, "relocated.dll", "wb");
	fwrite(file_buf, 1, import_end, out_file);
	fclose(out_file);

	printf("Writing relocated binary to disk as relocated.dll. Headers might still be invalid.\n");

	free(file_buf);
	free(import_section);
	free(reloc_section);
}

void relocator::scan_dumps() {

	printf("\nScanning dumps...\n");
	scan_section(TEXT);

	// format it a little more nicely
	printf("\n\n========================================\n");
	printf("Found %i references to exports\n", m_iats.size());
	printf("Found %i relocations\n", m_relocs.size());
	printf("Found %i direct memory references\n", m_memory_references.size());
	printf("========================================\n\n");

	printf("Writing results to disk...\n");
	json dump, iats, relocs, mem_refs;

	int i = 0;
	for (auto& it : m_relocs) {
		json v;
		v["OFFSET"] = it.offset;
		v["RVA"] = it.rva;

		relocs[i] = v;
		i++;
	}

	i = 0;
	for (auto& it : m_iats) {
		json v;
		v["OFFSET"] = it.offset;
		v["MODULE"] = it.import.module_name;
		v["EXPORT"] = it.import.export_name;
		v["RELATIVE"] = it.relative;

		iats[i] = v;
		i++;
	}

	i = 0;
	for (auto& it : m_memory_references) {
		json v;
		v["OFFSET"] = it.offset;
		v["MODULE"] = it.module_name;
		v["RVA"] = it.rva;

		mem_refs[i] = v;
		i++;
	}

	dump["RELOCS"] = relocs;
	dump["IAT"] = iats;
	dump["MEMREF"] = mem_refs;

	std::ofstream f("reloc_info.txt");
	f << dump.dump(1, '\t', true);

	printf("Results written to reloc_info.txt\n");
}

void relocator::scan_section(sections_t section, uintptr_t pad) {
	// just scan the whole image
	uintptr_t offset = 0;
	uintptr_t end = m_modules.at(0)->m_image_size;
	//uintptr_t offset = m_sections.sections[section].start_offset;
	//uintptr_t end = m_sections.sections[section].end_offset;

	// keep this as pure C pointers, they will get accessed a lot and this is faster than letting it go through STL
	int num_modules = m_modules.size();
	auto modules = m_modules.data();

	int num_relative_iats = 0;
	int num_iats = m_iats.size();
	int num_relocs = m_relocs.size();
	uintptr_t last_iat_address = -1;
	std::string last_iat_module = "";

	printf("\tSearching in range %X - %X\n", offset, end);

	while (offset < (end - sizeof(uintptr_t))) {
		// first scan for relocation
		// for reloc, require all of the loaded modules to have different values
		// also require all modules to have the same RVA
		bool is_reloc = true;
		uintptr_t reloc_rva = 0;
		for (int i = 0; i < num_modules; i++) {
			if (!is_reloc)
				break;

			auto fst_mod = modules[i];
			uintptr_t fst_val = *reinterpret_cast<uintptr_t*>(fst_mod->m_image_buf + offset);
			if (!fst_mod->module_contains_address(fst_val)) { // doesnt point to somewhere inside our own module, cant be reloc
				is_reloc = false;
				break;
			}

			reloc_rva = fst_mod->calculate_rva(fst_val);

			// sub loop for all the other modules, if we get a match we know it is not a relocation
			for (int k = 0; k < num_modules; k++) {
				if (k == i) // dont check against itself
					continue;

				auto snd_mod = modules[k];
				uintptr_t snd_val = *reinterpret_cast<uintptr_t*>(snd_mod->m_image_buf + offset);

				if (fst_val == snd_val) { // they are the same, not a relocation
					is_reloc = false;
					break;
				}

				// now check if its inside of the module
				if (!snd_mod->module_contains_address(snd_val)) {
					is_reloc = false;
					break;
				}

				// make sure the RVA is the same
				if (reloc_rva != snd_mod->calculate_rva(snd_val)) {
					is_reloc = false;
					break;
				}
			}
		}

		// check if it actually was a reloc
		if (is_reloc) {
			relocation_information reloc_info;
			reloc_info.offset = offset;
			reloc_info.rva = reloc_rva;
			m_relocs.push_back(reloc_info);

			m_relocation_rebuild_data[offset & ~(0xFFF)].push_back(offset);

			offset += sizeof(uintptr_t);
			continue;
		}

		// not a relocation, check for if its an export.
		// require 1 of the modules to be different
		// require all of the modules to point to the same export

		// get first module
		bool is_diff = false;
		auto fst_mod = modules[0];
		uintptr_t fst_val = *reinterpret_cast<uintptr_t*>(fst_mod->m_image_buf + offset);
		for (int i = 1; i < num_modules; i++) {
			auto snd_mod = modules[i];
			uintptr_t snd_val = *reinterpret_cast<uintptr_t*>(snd_mod->m_image_buf + offset);

			if (fst_val != snd_val) { // the modules differ, potential iat
				is_diff = true;
				break;
			}
		}

		// potentially an IAT, make sure ALL the modules point to the same export
		if (is_diff) {
			bool is_iat = false;
			bool is_relative_iat = false;
			auto fst_iat = fst_mod->get_export_for_address(fst_val); // see if it points to a module
			if (fst_iat) {
				for (int i = 1; i < num_modules; i++) {
					auto snd_mod = modules[i];
					uintptr_t snd_val = *reinterpret_cast<uintptr_t*>(snd_mod->m_image_buf + offset);
					auto snd_iat = snd_mod->get_export_for_address(snd_val);
					if (!snd_iat) {
						is_iat = false;
						break;
					}

					if (fst_iat->module_name.compare(snd_iat->module_name)) { // iat module doesnt match
						is_iat = false;
						break;
					}

					if (fst_iat->export_name.compare(snd_iat->export_name)) { // export name doesnt match
						is_iat = false;
						break;
					}

					// passed all checks, potential iat
					is_iat = true;
				}
			}

			// not normal iat, is it a relative one?
			if (!is_iat) {
				uint8_t prior_byte = *reinterpret_cast<uint8_t*>(fst_mod->m_image_buf + offset - 1);
				uintptr_t final_addr = fst_val + fst_mod->m_sections.base_address + offset + 4;
				fst_iat = fst_mod->get_export_for_address(final_addr); // see if it points to a module
				if ((prior_byte == 0xE8 || prior_byte == 0xE9) && fst_iat) { // relative?;
					for (int i = 1; i < num_modules; i++) {
						auto snd_mod = modules[i];
						uint8_t snd_prior_byte = *reinterpret_cast<uint8_t*>(snd_mod->m_image_buf + offset - 1);
						uintptr_t snd_val = *reinterpret_cast<uintptr_t*>(snd_mod->m_image_buf + offset);
						uintptr_t snd_final_addr = snd_val + snd_mod->m_sections.base_address + offset + 4;
						auto snd_iat = snd_mod->get_export_for_address(snd_final_addr);
						if (!snd_iat || snd_prior_byte != prior_byte) {
							is_iat = false;
							break;
						}

						if (fst_iat->module_name.compare(snd_iat->module_name)) { // iat module doesnt match
							is_iat = false;
							break;
						}

						if (fst_iat->export_name.compare(snd_iat->export_name)) { // export name doesnt match
							is_iat = false;
							break;
						}

						// passed all checks, potential iat
						is_iat = true;
						is_relative_iat = true;
						num_relative_iats++;
					}
				}
			}

			// if all checks passed, add the iat
			if (is_iat) {
				iat_information iat_info;
				iat_info.import = *fst_iat;
				iat_info.offset = offset;
				iat_info.relative = is_relative_iat;

				// get information used for IAT rebuilding
				if (!is_relative_iat) {
					// if its not the next "address" in memory, or different module its gonna be be a new ImportDir
					if ((offset - last_iat_address) != sizeof(uintptr_t) || last_iat_module.compare(fst_iat->module_name)) {
						m_iat_rebuild_data.push_back(std::vector<iat_information>());
					}
					m_iat_rebuild_data.back().push_back(iat_info);
				}

				m_iats.push_back(iat_info);

				offset += sizeof(uintptr_t);
				continue;
			}
		}


		// might be memory ref
		if (is_diff) {
			bool is_mem_ref = false;
			auto fst_mem_ref = fst_mod->get_direct_memory_reference(fst_val); // see if it points to a module
			if (fst_mem_ref.valid) {
				for (int i = 1; i < num_modules; i++) {
					auto snd_mod = modules[i];
					uintptr_t snd_val = *reinterpret_cast<uintptr_t*>(snd_mod->m_image_buf + offset);
					auto snd_mem_ref = snd_mod->get_direct_memory_reference(snd_val);
					if (!snd_mem_ref.valid) {
						is_mem_ref = false;
						break;
					}

					if (fst_mem_ref.module_name.compare(snd_mem_ref.module_name)) { // iat module doesnt match
						is_mem_ref = false;
						break;
					}

					if (fst_mem_ref.rva != snd_mem_ref.rva) { // export name doesnt match
						is_mem_ref = false;
						break;
					}

					// passed all checks, potential iat
					is_mem_ref = true;
				}
			}
		
			if (is_mem_ref) {
				fst_mem_ref.offset = offset;
				m_memory_references.push_back(fst_mem_ref);
			}
		}

		// neither relocation nor export, move onto the next byte.
		offset += pad;
	}

	printf("\tFound %i IATs (%i relative IATS)\n\tFound %i relocations\n\n", m_iats.size() - num_iats, num_relative_iats, m_relocs.size() - num_relocs);
}

uint8_t* relocator::create_reloc_section(size_t* out_size) {
	printf("Creating relocation section...\n");

	size_t num_base_relocs = m_relocation_rebuild_data.size();
	size_t needed_size = (num_base_relocs + 1) * sizeof(IMAGE_BASE_RELOCATION) + m_relocs.size() * sizeof(uint16_t); // amount of baserelocs + 16bit for each entry
	PAD_TO_BOUNDARY(needed_size, 0x1000);

	uint8_t* buf = (uint8_t*)malloc(needed_size);
	if (!buf)
		return nullptr;

	IMAGE_BASE_RELOCATION base_reloc;
	int i = 0;
	for (auto& it : m_relocation_rebuild_data) {
		size_t num_entries = it.second.size();

		base_reloc.SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION) + num_entries * sizeof(uint16_t);
		base_reloc.VirtualAddress = it.first;

		*(IMAGE_BASE_RELOCATION*)(buf + i * sizeof(IMAGE_BASE_RELOCATION)) = base_reloc;

		for (int j = 0; j < num_entries; j++) {
			*(uint16_t*)(buf + sizeof(IMAGE_BASE_RELOCATION) + j * sizeof(uint16_t)) = it.second.at(j) - base_reloc.VirtualAddress;
		}

		i++;
	}

	// write the "null" termination for it 
	base_reloc.VirtualAddress = 0;
	base_reloc.SizeOfBlock = 0;
	*(IMAGE_BASE_RELOCATION*)(buf + num_base_relocs * sizeof(IMAGE_BASE_RELOCATION)) = base_reloc;

	if (out_size)
		*out_size = needed_size;

	return buf;
}

uint8_t* relocator::create_import_section(size_t* out_size, uintptr_t section_base) {
	if (!m_iat_rebuild_data.size())
		return nullptr;

	printf("Creating import directory...\n");

	// calculating the size of the section we need to calculate
	uintptr_t names_size = 0, ofts_size = 0, importdir_names_size = 0;
	uintptr_t importdirs_size = (m_iat_rebuild_data.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR); // +1 for "null" terminator
	for (auto& dir : m_iat_rebuild_data) { // iterate the import directories
		ofts_size += (dir.size() + 1) * sizeof(IMAGE_THUNK_DATA); // Make space for the OriginalFirstThunk's (+1 for null terminator for each OFT)
		importdir_names_size += dir.back().import.module_name.length() + 1; // make space for the ImportDir module names
		for (auto& thunk : dir) {
			names_size += sizeof(WORD) + thunk.import.export_name.length() + 1; // include null terminator
		}
	}

	uintptr_t section_size = names_size + ofts_size + importdirs_size + importdir_names_size;
	PAD_TO_BOUNDARY(section_size, 0x1000);

	uint8_t* buf = (uint8_t*)malloc(section_size);
	if (!buf)
		return nullptr;

	// Create the ImportDirs, OFTs and copy the names into place, in order: ImportDirs, ImportDirNames, OFTs, IMPORT_BY_NAMEs
	uintptr_t import_dir_offset = 0, import_dir_name_offset = 0, oft_offset = 0, by_name_offset = 0;

	IMAGE_IMPORT_DESCRIPTOR desc;
	desc.TimeDateStamp = 0;
	desc.ForwarderChain = -1;
	for (auto& dir : m_iat_rebuild_data) {
		auto first_firstthunk = dir.at(0);
		// setup the import descriptor and copy it int position
		desc.FirstThunk = first_firstthunk.offset; // firstthunk
		desc.OriginalFirstThunk = section_base + importdirs_size + importdir_names_size + oft_offset; // where we will start copying OFTs for this dir 
		desc.Name = section_base + importdirs_size + import_dir_name_offset;
		memcpy(buf + importdirs_size + import_dir_name_offset, first_firstthunk.import.module_name.c_str(), first_firstthunk.import.module_name.length() + 1);
		import_dir_name_offset += first_firstthunk.import.module_name.length() + 1;

		// copy the descriptor into memory
		memcpy(buf + import_dir_offset, &desc, sizeof(IMAGE_IMPORT_DESCRIPTOR));
		import_dir_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);

		// write all the OFTs and names
		IMAGE_THUNK_DATA oft;
		IMAGE_IMPORT_BY_NAME by_name;
		by_name.Hint = 0;
		for (auto& thunk : dir) {
			// copy the OFT into place
			oft.u1.AddressOfData = section_base + importdirs_size + importdir_names_size + ofts_size + by_name_offset;
			memcpy(buf + importdirs_size + importdir_names_size + oft_offset, &oft, sizeof(IMAGE_THUNK_DATA));
			oft_offset += sizeof(IMAGE_THUNK_DATA);

			// copy name into place
			*(WORD*)(buf + importdirs_size + importdir_names_size + ofts_size + by_name_offset) = 0; // "Hint"
			memcpy(buf + importdirs_size + importdir_names_size + ofts_size + by_name_offset + sizeof(WORD), thunk.import.export_name.c_str(), thunk.import.export_name.length() + 1);
			by_name_offset += sizeof(WORD) + thunk.import.export_name.length() + 1;
		}
		// OFT null terminator:
		oft.u1.AddressOfData = 0;
		memcpy(buf + importdirs_size + importdir_names_size + oft_offset, &oft, sizeof(IMAGE_THUNK_DATA)); 
		oft_offset += sizeof(IMAGE_THUNK_DATA);
	}
	// importdir null terminator:
	desc.Characteristics = 0;
	memcpy(buf + import_dir_offset, &desc, sizeof(IMAGE_IMPORT_DESCRIPTOR));
	import_dir_offset += sizeof(IMAGE_IMPORT_DESCRIPTOR);

	if (out_size)
		*out_size = section_size;

	printf("ImportDir: %X, size: %X\nOFT: %X\nIAT Directory: %X size: %X", section_base, importdirs_size, section_base + importdirs_size + importdir_names_size, m_iat_rebuild_data.at(0).at(0).offset, (m_iat_rebuild_data.back().back().offset - m_iat_rebuild_data.at(0).at(0).offset) + sizeof(uintptr_t));

	return buf;
}

module_relocation_information* relocator::get_module(std::string folder_path) {
	auto mod = new module_relocation_information();
	if (!mod->init(folder_path, &m_sections)) {
		delete mod;
		return nullptr;
	}

	return mod;
}