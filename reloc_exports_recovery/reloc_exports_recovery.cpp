#include "pch.h"
#include "reloc_exports_recovery.h"
#include "module_relocation_information.h"
#include "relocator.h"

int main()
{
    auto rec = new relocator();

    rec->start();

    delete rec;
    std::getchar();
    return 0;
}

