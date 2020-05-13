#include "pch.h"
#include "relocator.h"

relocator::relocator() {
	m_relocs.clear();
	m_iats.clear();
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
}

void relocator::scan_dumps() {

	printf("\nScanning dumps...\n");
	scan_section(TEXT);

	// format it a little more nicely
	printf("\n\n========================================\n");
	printf("Found %i references to exports\n", m_iats.size());
	printf("Found %i relocations\n", m_relocs.size());
	printf("========================================\n\n");

	printf("Writing results to disk...\n");
	json dump, iats, relocs;

	int i = 0;
	for (auto& it : m_relocs) {
		json v;
		v["OFFSET"] = it.reloc_address;
		v["RVA"] = it.rva;

		relocs[i] = v;
		i++;
	}

	i = 0;
	for (auto& it : m_iats) {
		json v;
		v["OFFSET"] = it.import_address;
		v["MODULE"] = it.import.module_name;
		v["EXPORT"] = it.import.export_name;

		iats[i] = v;
		i++;
	}

	dump["RELOCS"] = relocs;
	dump["IAT"] = iats;

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

	int num_iats = m_iats.size();
	int num_relocs = m_relocs.size();
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
			reloc_info.reloc_address = offset;
			reloc_info.rva = reloc_rva;
			m_relocs.push_back(reloc_info);

			offset += sizeof(uintptr_t);
			continue;
		}

		// not a relocation, check for if its an export.
		// require 1 of the modules to be different
		// require all of the modules to point to the same export

		// get first module
		bool potential_iat = false;
		auto fst_mod = modules[0];
		uintptr_t fst_val = *reinterpret_cast<uintptr_t*>(fst_mod->m_image_buf + offset);
		for (int i = 1; i < num_modules; i++) {
			auto snd_mod = modules[i];
			uintptr_t snd_val = *reinterpret_cast<uintptr_t*>(snd_mod->m_image_buf + offset);

			if (fst_val != snd_val) { // the modules differ, potential iat
				potential_iat = true;
				break;
			}
		}

		// potentially an IAT, make sure ALL the modules point to the same export
		if (potential_iat) {
			bool is_iat = false;
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

			// if all checks passed, add the iat
			if (is_iat) {
				iat_information iat_info;
				iat_info.import = *fst_iat;
				iat_info.import_address = offset;

				m_iats.push_back(iat_info);

				offset += sizeof(uintptr_t);
				continue;
			}
		}

		// neither relocation nor export, move onto the next byte.
		offset += pad;
	}

	printf("\tFound %i export references\n\tFound %i relocations\n\n", m_iats.size() - num_iats, m_relocs.size() - num_relocs);
}

module_relocation_information* relocator::get_module(std::string folder_path) {
	auto mod = new module_relocation_information();
	if (!mod->init(folder_path, &m_sections)) {
		delete mod;
		return nullptr;
	}

	return mod;
}