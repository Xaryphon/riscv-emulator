#include "elf_loader.h"

#include <assert.h>
#include <elf.h>
#include <stdlib.h>
#include <string.h>

#include "logger.h"

#define RV_OFFSET_POINTER(ptr, offset) ((void*)((char*)(ptr) + (offset)))

bool should_load_segment(uint32_t p_type) {
    return p_type == PT_LOAD;
}

bool rv_load_elf32(void *ptr, size_t size, rv_MemoryBuilder *builder, rv_UInt base_address, rv_UInt *entry) {
    if (size < sizeof(Elf32_Ehdr))
        return false;

    Elf32_Ehdr *ehdr = ptr;
    if (ehdr->e_type != ET_EXEC || ehdr->e_machine != EM_RISCV || ehdr->e_version != EV_CURRENT)
        return false;

    // FIXME: Handle e_flags

    if (ehdr->e_ehsize != sizeof(Elf32_Ehdr)) {
        rv_warn("FIXME: Load elf files when ehdr size != sizeof(Elf32_Ehdr)");
        return false;
    }

    if (ehdr->e_phoff == 0)
        return false;

    if (ehdr->e_phnum == PN_XNUM) {
        rv_warn("FIXME: Load elf files with more than PN_XNUM program headers");
        return false;
    }

    if (ehdr->e_phentsize != sizeof(Elf32_Phdr)) {
        rv_warn("FIXME: Load elf files when phdr size != sizeof(Elf32_Phdr)");
        return false;
    }

    if (size < ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize)
        return false;

    size_t load_segments = 0;
    rv_UInt required_space = 0;
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        Elf32_Phdr *phdr = RV_OFFSET_POINTER(ptr, ehdr->e_phoff + ehdr->e_phentsize * i);

        if (should_load_segment(phdr->p_type)) {
            if (phdr->p_memsz != 0) {
                rv_UInt file_end = phdr->p_offset + phdr->p_filesz;
                if (size < file_end)
                    return false;

                if (phdr->p_filesz > phdr->p_memsz) {
                    rv_warn("FIXME: Handle p_filesz > p_memsz");
                    return false;
                } else if (phdr->p_filesz != 0 && phdr->p_filesz != phdr->p_memsz) {
                    rv_warn("FIXME: Handle p_filesz != p_memsz for non-zero p_filesz");
                    return false;
                }

                rv_UInt virt_end = phdr->p_vaddr + phdr->p_memsz;
                if (virt_end > required_space) {
                    required_space = virt_end;
                    load_segments += 1;
                }
            }
        } else if (phdr->p_type != PT_NULL && phdr->p_type != PT_RISCV_ATTRIBUTES) {
            // FIXME: Handle PT_RISCV_ATTRIBUTES segment
            rv_warn("FIXME: Ignoring segment %zu of type 0x%x", i, phdr->p_type);
        }
    }

    if (!rv_memory_can_fit(builder, base_address, required_space)) {
        rv_error("Cannot fit segments in memory");
        return false;
    }

    if (!rv_memory_grow(builder, load_segments)) {
        rv_error("Failed to reserve space for memory devices");
        return false;
    }

    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        Elf32_Phdr *phdr = RV_OFFSET_POINTER(ptr, ehdr->e_phoff + ehdr->e_phentsize * i);
        if (!should_load_segment(phdr->p_type) || phdr->p_memsz == 0)
            continue;

        // TODO: mmap segments
        void *data = malloc(phdr->p_memsz);
        assert(data != NULL); // FIXME: Handle error

        memcpy(data, RV_OFFSET_POINTER(ptr, phdr->p_offset), phdr->p_filesz);
        memset(RV_OFFSET_POINTER(data, phdr->p_filesz), 0, phdr->p_memsz - phdr->p_filesz);

        rv_MemoryDevice *mem = rv_memory_push(builder, base_address + phdr->p_vaddr, phdr->p_memsz);
        assert(mem != NULL);
        mem->data = data;
        mem->flags = RV_MEMORY_SHOULD_FREE;
        if (phdr->p_flags & PF_X)
            mem->flags |= RV_MEMORY_EXECUTE;
        if (phdr->p_flags & PF_W)
            mem->flags |= RV_MEMORY_WRITE;
        if (phdr->p_flags & PF_R)
            mem->flags |= RV_MEMORY_READ;
    }

    if (ehdr->e_entry != 0)
        *entry = base_address + ehdr->e_entry;
    else
        *entry = 0;

    return true;
}

bool rv_load_elf64(void *ptr, size_t size, rv_MemoryBuilder *builder, rv_UInt base_address, rv_UInt *entry) {
    if (size < sizeof(Elf64_Ehdr))
        return false;

    Elf64_Ehdr *ehdr = ptr;
    if (ehdr->e_type != ET_EXEC || ehdr->e_machine != EM_RISCV || ehdr->e_version != EV_CURRENT)
        return false;

    // FIXME: Handle e_flags

    if (ehdr->e_ehsize != sizeof(Elf64_Ehdr)) {
        rv_warn("FIXME: Load elf files when ehdr size != sizeof(Elf64_Ehdr)");
        return false;
    }

    if (ehdr->e_phoff == 0)
        return false;

    if (ehdr->e_phnum == PN_XNUM) {
        rv_warn("FIXME: Load elf files with more than PN_XNUM program headers");
        return false;
    }

    if (ehdr->e_phentsize != sizeof(Elf64_Phdr)) {
        rv_warn("FIXME: Load elf files when phdr size != sizeof(Elf64_Phdr)");
        return false;
    }

    if (size < ehdr->e_phoff + ehdr->e_phnum * ehdr->e_phentsize)
        return false;

    size_t load_segments = 0;
    rv_UInt required_space = 0;
    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *phdr = RV_OFFSET_POINTER(ptr, ehdr->e_phoff + ehdr->e_phentsize * i);

        if (should_load_segment(phdr->p_type)) {
            if (phdr->p_memsz != 0) {
                rv_UInt file_end = phdr->p_offset + phdr->p_filesz;
                if (size < file_end)
                    return false;

                if (phdr->p_filesz > phdr->p_memsz) {
                    rv_warn("FIXME: Handle p_filesz > p_memsz");
                    return false;
                } else if (phdr->p_filesz != 0 && phdr->p_filesz != phdr->p_memsz) {
                    rv_warn("FIXME: Handle p_filesz != p_memsz for non-zero p_filesz");
                    return false;
                }

                rv_UInt virt_end = phdr->p_vaddr + phdr->p_memsz;
                if (virt_end > required_space) {
                    required_space = virt_end;
                    load_segments += 1;
                }
            }
        } else if (phdr->p_type != PT_NULL && phdr->p_type != PT_RISCV_ATTRIBUTES) {
            // FIXME: Handle PT_RISCV_ATTRIBUTES segment
            rv_warn("FIXME: Ignoring segment %zu of type 0x%x", i, phdr->p_type);
        }
    }

    if (!rv_memory_can_fit(builder, base_address, required_space)) {
        rv_error("Cannot fit segments in memory");
        return false;
    }

    if (!rv_memory_grow(builder, load_segments)) {
        rv_error("Failed to reserve space for memory devices");
        return false;
    }

    for (size_t i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *phdr = RV_OFFSET_POINTER(ptr, ehdr->e_phoff + ehdr->e_phentsize * i);
        if (!should_load_segment(phdr->p_type) || phdr->p_memsz == 0)
            continue;

        // TODO: mmap segments
        void *data = malloc(phdr->p_memsz);
        assert(data != NULL); // FIXME: Handle error

        memcpy(data, RV_OFFSET_POINTER(ptr, phdr->p_offset), phdr->p_filesz);
        memset(RV_OFFSET_POINTER(data, phdr->p_filesz), 0, phdr->p_memsz - phdr->p_filesz);

        rv_MemoryDevice *mem = rv_memory_push(builder, base_address + phdr->p_vaddr, phdr->p_memsz);
        assert(mem != NULL);
        mem->data = data;
        mem->flags = RV_MEMORY_SHOULD_FREE;
        if (phdr->p_flags & PF_X)
            mem->flags |= RV_MEMORY_EXECUTE;
        if (phdr->p_flags & PF_W)
            mem->flags |= RV_MEMORY_WRITE;
        if (phdr->p_flags & PF_R)
            mem->flags |= RV_MEMORY_READ;
    }

    if (ehdr->e_entry != 0)
        *entry = base_address + ehdr->e_entry;
    else
        *entry = 0;

    return true;
}

bool rv_load_elf(void *ptr, size_t size, rv_MemoryBuilder *builder, rv_UInt address, rv_UInt *entry) {
    if (size < EI_NIDENT)
        return false;

    unsigned char *e_ident = ptr;
    if (e_ident[EI_MAG0] != ELFMAG0 || e_ident[EI_MAG1] != ELFMAG1 || e_ident[EI_MAG2] != ELFMAG2 || e_ident[EI_MAG3] != ELFMAG3)
        return false;

    if (e_ident[EI_DATA] != ELFDATA2LSB || e_ident[EI_VERSION] != EV_CURRENT || e_ident[EI_ABIVERSION] != 0)
        return false;

    // NOTE: We currently ignore EI_OSABI

    switch (e_ident[EI_CLASS]) {
    case ELFCLASS32: return rv_load_elf32(ptr, size, builder, address, entry);
    case ELFCLASS64: return rv_load_elf64(ptr, size, builder, address, entry);
    default: return false;
    }
}
