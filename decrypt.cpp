// e7d81637d42c4b23

#define _CRT_SECURE_NO_WARNINGS // made by pibbly -> discord.gg/zzzzhub
#include <stdio.h> // made by pibbly -> discord.gg/zzzzhub
#include <stdint.h> // made by pibbly -> discord.gg/zzzzhub
#include <string.h> // made by pibbly -> discord.gg/zzzzhub
#include <vector> // made by pibbly -> discord.gg/zzzzhub
#include <string> // made by pibbly -> discord.gg/zzzzhub

static const uint32_t offset_start = 0x201000; // made by pibbly -> discord.gg/zzzzhub
static const uint32_t offset_end = 0x401000; // made by pibbly -> discord.gg/zzzzhub
static const uint32_t keys = 0x170760; // made by pibbly -> discord.gg/zzzzhub
static const uint32_t keys_file_off = 0x15D560; // made by pibbly -> discord.gg/zzzzhub (e7 DLL on-disk)
static const uint32_t size = 0x2004; // made by pibbly -> discord.gg/zzzzhub
static const uint32_t loops = 32; // made by pibbly -> discord.gg/zzzzhub

static uint64_t rotl(uint64_t v, int n) { // made by pibbly -> discord.gg/zzzzhub
    return (v << n) | (v >> (64 - n)); // made by pibbly -> discord.gg/zzzzhub
}

static bool slurp(const char* path, std::vector<uint8_t>& buf) { // made by pibbly -> discord.gg/zzzzhub
    FILE* f = fopen(path, "rb"); // made by pibbly -> discord.gg/zzzzhub
    if (!f) return false; // made by pibbly -> discord.gg/zzzzhub
    fseek(f, 0, SEEK_END); // made by pibbly -> discord.gg/zzzzhub
    long n = ftell(f); // made by pibbly -> discord.gg/zzzzhub
    if (n <= 0) { fclose(f); return false; } // made by pibbly -> discord.gg/zzzzhub
    fseek(f, 0, SEEK_SET); // made by pibbly -> discord.gg/zzzzhub
    buf.resize((size_t)n); // made by pibbly -> discord.gg/zzzzhub
    size_t got = fread(buf.data(), 1, buf.size(), f); // made by pibbly -> discord.gg/zzzzhub
    fclose(f); // made by pibbly -> discord.gg/zzzzhub
    return got == buf.size(); // made by pibbly -> discord.gg/zzzzhub
}

static bool find_sec(const std::vector<uint8_t>& pe, const char* want, uint32_t& va, uint32_t& raw, uint32_t& sz) { // made by pibbly -> discord.gg/zzzzhub
    if (pe.size() < 0x40) return false; // made by pibbly -> discord.gg/zzzzhub
    uint32_t peoff = *(uint32_t*)&pe[0x3c]; // made by pibbly -> discord.gg/zzzzhub
    if (peoff + 0x18 > pe.size()) return false; // made by pibbly -> discord.gg/zzzzhub
    if (memcmp(&pe[peoff], "PE\0\0", 4)) return false; // made by pibbly -> discord.gg/zzzzhub
    uint16_t nsec = *(uint16_t*)&pe[peoff + 6]; // made by pibbly -> discord.gg/zzzzhub
    uint16_t optsz = *(uint16_t*)&pe[peoff + 20]; // made by pibbly -> discord.gg/zzzzhub
    size_t off = peoff + 24 + optsz; // made by pibbly -> discord.gg/zzzzhub
    for (int i = 0; i < nsec; i++) { // made by pibbly -> discord.gg/zzzzhub
        size_t o = off + (size_t)i * 40; // made by pibbly -> discord.gg/zzzzhub
        if (o + 40 > pe.size()) return false; // made by pibbly -> discord.gg/zzzzhub
        char name[9] = { 0 }; // made by pibbly -> discord.gg/zzzzhub
        memcpy(name, &pe[o], 8); // made by pibbly -> discord.gg/zzzzhub
        if (_stricmp(name, want)) continue; // made by pibbly -> discord.gg/zzzzhub
        sz = *(uint32_t*)&pe[o + 8]; // made by pibbly -> discord.gg/zzzzhub
        va = *(uint32_t*)&pe[o + 12]; // made by pibbly -> discord.gg/zzzzhub
        raw = *(uint32_t*)&pe[o + 20]; // made by pibbly -> discord.gg/zzzzhub
        return true; // made by pibbly -> discord.gg/zzzzhub
    }
    return false; // made by pibbly -> discord.gg/zzzzhub
}

static bool rva_to_raw(const std::vector<uint8_t>& pe, uint32_t rva, uint32_t& raw_out) { // made by pibbly -> discord.gg/zzzzhub
    if (pe.size() < 0x40) return false; // made by pibbly -> discord.gg/zzzzhub
    uint32_t peoff = *(uint32_t*)&pe[0x3c]; // made by pibbly -> discord.gg/zzzzhub
    if (peoff + 0x18 > pe.size()) return false; // made by pibbly -> discord.gg/zzzzhub
    if (memcmp(&pe[peoff], "PE\0\0", 4)) return false; // made by pibbly -> discord.gg/zzzzhub
    uint16_t nsec = *(uint16_t*)&pe[peoff + 6]; // made by pibbly -> discord.gg/zzzzhub
    uint16_t optsz = *(uint16_t*)&pe[peoff + 20]; // made by pibbly -> discord.gg/zzzzhub
    size_t off = peoff + 24 + optsz; // made by pibbly -> discord.gg/zzzzhub
    for (int i = 0; i < nsec; i++) { // made by pibbly -> discord.gg/zzzzhub
        size_t o = off + (size_t)i * 40; // made by pibbly -> discord.gg/zzzzhub
        if (o + 40 > pe.size()) break; // made by pibbly -> discord.gg/zzzzhub
        uint32_t va = *(uint32_t*)&pe[o + 12]; // made by pibbly -> discord.gg/zzzzhub
        uint32_t vsz = *(uint32_t*)&pe[o + 8]; // made by pibbly -> discord.gg/zzzzhub
        uint32_t raw = *(uint32_t*)&pe[o + 20]; // made by pibbly -> discord.gg/zzzzhub
        if (rva < va || rva >= va + vsz) continue; // made by pibbly -> discord.gg/zzzzhub
        raw_out = raw + (rva - va); // made by pibbly -> discord.gg/zzzzhub
        return true; // made by pibbly -> discord.gg/zzzzhub
    }
    return false; // made by pibbly -> discord.gg/zzzzhub
}

static void decrypt_page(uint8_t* page, uint32_t pid, const uint8_t* w1, const uint8_t* w2) { // made by pibbly -> discord.gg/zzzzhub
    uint64_t a, b, c, d; // made by pibbly -> discord.gg/zzzzhub
    memcpy(&a, w1, 8); // made by pibbly -> discord.gg/zzzzhub
    memcpy(&b, w1 + 8, 8); // made by pibbly -> discord.gg/zzzzhub
    memcpy(&c, w2, 8); // made by pibbly -> discord.gg/zzzzhub
    memcpy(&d, w2 + 8, 8); // made by pibbly -> discord.gg/zzzzhub

    uint64_t rax = ((uint64_t)(pid & 0xffff)) << 44; // made by pibbly -> discord.gg/zzzzhub
    int pos = 16; // made by pibbly -> discord.gg/zzzzhub

    for (int i = 0; i < 128; i++) { // made by pibbly -> discord.gg/zzzzhub
        uint64_t mask = rax; // made by pibbly -> discord.gg/zzzzhub
        uint64_t lane[2] = { ~mask, mask }; // made by pibbly -> discord.gg/zzzzhub
        uint64_t A[2], B[2], o1[2], o2[2]; // made by pibbly -> discord.gg/zzzzhub
        memcpy(A, page + pos - 16, 16); // made by pibbly -> discord.gg/zzzzhub
        memcpy(B, page + pos, 16); // made by pibbly -> discord.gg/zzzzhub

        for (int ln = 0; ln < 2; ln++) { // made by pibbly -> discord.gg/zzzzhub
            uint64_t av = A[ln], bv = B[ln], mv = lane[ln]; // made by pibbly -> discord.gg/zzzzhub
            uint64_t C = ((rotl(av ^ b, 1) * b) - (av >> 2)) ^ bv; // made by pibbly -> discord.gg/zzzzhub
            uint64_t D = ((rotl(~C, 51) + a) * c) ^ av; // made by pibbly -> discord.gg/zzzzhub
            uint64_t E = rotl(D, 46) ^ C ^ (rotl(b ^ D, 3) * d); // made by pibbly -> discord.gg/zzzzhub
            uint64_t G = ((rotl(E + a, 36) * c) - rotl(E, 57)) ^ D; // made by pibbly -> discord.gg/zzzzhub
            uint64_t H = ((G - b) ^ d) ^ E; // made by pibbly -> discord.gg/zzzzhub
            o2[ln] = H ^ mv; // made by pibbly -> discord.gg/zzzzhub
            o1[ln] = mv ^ ((H >> 3) + ((H ^ c) * a)) ^ G; // made by pibbly -> discord.gg/zzzzhub
        }

        memcpy(page + pos - 16, o1, 16); // made by pibbly -> discord.gg/zzzzhub
        memcpy(page + pos, o2, 16); // made by pibbly -> discord.gg/zzzzhub
        rax += 0x2000000000ULL; // made by pibbly -> discord.gg/zzzzhub
        pos += 32; // made by pibbly -> discord.gg/zzzzhub
    }
}

int main(int argc, char** argv) { // made by pibbly -> discord.gg/zzzzhub
    std::string dir = "C:\\Users\\zzzz\\Downloads\\WEAO-LIVE-WindowsPlayer-version-e7d81637d42c4b23"; // adjust path if needed
    const char* outp = "region1_512.bin"; // made by pibbly -> discord.gg/zzzzhub

    if (argc >= 2) dir = argv[1]; // made by pibbly -> discord.gg/zzzzhub
    if (argc >= 3) outp = argv[2]; // made by pibbly -> discord.gg/zzzzhub

    std::string exep = dir + "\\RobloxPlayerBeta.exe"; // made by pibbly -> discord.gg/zzzzhub
    std::string dllp = dir + "\\RobloxPlayerBeta.dll"; // made by pibbly -> discord.gg/zzzzhub

    std::vector<uint8_t> exe, dll; // made by pibbly -> discord.gg/zzzzhub
    if (!slurp(exep.c_str(), exe)) { // made by pibbly -> discord.gg/zzzzhub
        printf("cant read exe\n"); // made by pibbly -> discord.gg/zzzzhub
        return 1; // made by pibbly -> discord.gg/zzzzhub
    }
    if (!slurp(dllp.c_str(), dll)) { // made by pibbly -> discord.gg/zzzzhub
        printf("cant read dll\n"); // made by pibbly -> discord.gg/zzzzhub
        return 1; // made by pibbly -> discord.gg/zzzzhub
    }

    uint32_t text_va, text_raw, text_sz; // made by pibbly -> discord.gg/zzzzhub
    if (!find_sec(exe, ".text", text_va, text_raw, text_sz)) { // made by pibbly -> discord.gg/zzzzhub
        printf("no .text\n"); // made by pibbly -> discord.gg/zzzzhub
        return 1; // made by pibbly -> discord.gg/zzzzhub
    }

    uint32_t tbl_off = keys_file_off; // made by pibbly -> discord.gg/zzzzhub
    uint32_t mapped = 0; // made by pibbly -> discord.gg/zzzzhub
    if (rva_to_raw(dll, keys, mapped)) tbl_off = mapped; // made by pibbly -> discord.gg/zzzzhub

    size_t tbl_len = (size_t)size * loops; // made by pibbly -> discord.gg/zzzzhub
    if (tbl_off + tbl_len > dll.size()) { // made by pibbly -> discord.gg/zzzzhub
        printf("key table bad for this build \n", tbl_off); // made by pibbly -> discord.gg/zzzzhub
        return 1; // made by pibbly -> discord.gg/zzzzhub
    }

    const uint8_t* tbl = dll.data() + tbl_off; // made by pibbly -> discord.gg/zzzzhub
    std::vector<uint8_t> out(offset_end - offset_start, 0xcc); // made by pibbly -> discord.gg/zzzzhub
    int done = 0; // made by pibbly -> discord.gg/zzzzhub

    printf("keys=0x%X keys_off=0x%X text_va=0x%X\n", keys, tbl_off, text_va); // made by pibbly -> discord.gg/zzzzhub

    for (uint32_t rva = offset_start; rva < offset_end; rva += 0x1000) { // made by pibbly -> discord.gg/zzzzhub
        uint32_t rel = rva - text_va; // made by pibbly -> discord.gg/zzzzhub
        if (rel + 0x1000 > text_sz || (size_t)text_raw + rel + 0x1000 > exe.size()) // made by pibbly -> discord.gg/zzzzhub
            continue; // made by pibbly -> discord.gg/zzzzhub

        uint8_t page[0x1000]; // made by pibbly -> discord.gg/zzzzhub
        memcpy(page, exe.data() + text_raw + rel, 0x1000); // made by pibbly -> discord.gg/zzzzhub

        uint32_t pid = rva >> 12; // made by pibbly -> discord.gg/zzzzhub
        uint32_t slot = (pid % size) * loops; // made by pibbly -> discord.gg/zzzzhub
        decrypt_page(page, pid, tbl + slot, tbl + slot + 16); // made by pibbly -> discord.gg/zzzzhub

        memcpy(out.data() + (rva - offset_start), page, 0x1000); // made by pibbly -> discord.gg/zzzzhub
        done++; // made by pibbly -> discord.gg/zzzzhub
    }

    FILE* f = fopen(outp, "wb"); // made by pibbly -> discord.gg/zzzzhub
    if (!f) { // made by pibbly -> discord.gg/zzzzhub
        printf("cant write %s\n", outp); // made by pibbly -> discord.gg/zzzzhub
        return 1; // made by pibbly -> discord.gg/zzzzhub
    }
    fwrite(out.data(), 1, out.size(), f); // made by pibbly -> discord.gg/zzzzhub
    fclose(f); // made by pibbly -> discord.gg/zzzzhub

    printf("%d pages -> %s\n", done, outp); // made by pibbly -> discord.gg/zzzzhub
    return done == 512 ? 0 : 2; // made by pibbly -> discord.gg/zzzzhub
}