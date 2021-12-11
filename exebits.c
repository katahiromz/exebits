#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef _WIN32
    #include <windows.h>
    #include <imagehlp.h>
#else
  #include "won32.h"
#endif
#include <stdbool.h>

void show_version(void)
{
    puts("exebits version 0.1");
}

void show_help(void)
{
    puts("exebits --- Check the bits of an executable file.\n"
         "\n"
         "Usage: exebits [options] your_file.exe\n"
         "Options:\n"
         "    --verbose       Make the operation more talkative.\n"
         "    --bits XXX      Examinate the exe bits (XXX is 16, 32, or 64).\n"
         "\n"
         "If no options, it checks whether the file is an executable.");
}

int exebits(const char *file, int expected_bits, bool verbose)
{
    bool ret = false, bits64 = false;
    int real_bits = 0;
    FILE *fp;
    IMAGE_DOS_HEADER dos;
    DWORD Signature;
    IMAGE_FILE_HEADER coff;
    IMAGE_OPTIONAL_HEADER32 opt32;
    IMAGE_OPTIONAL_HEADER64 opt64;
#ifdef _WIN32
    DWORD HeaderSum, CheckSum;
#endif

    do
    {
        fp = fopen(file, "rb");
        if (!fp)
        {
            printf("exebits: error: Unable to open file '%s'.\n", file);
            break;
        }

        if (verbose)
            printf("exebits: Checking file '%s':\n", file);

        if (!fread(&dos, sizeof(dos), 1, fp))
        {
            printf("exebits: error: Unable to read dos header of file '%s'.\n", file);
            break;
        }

        if (verbose)
            printf("exebits: dos.e_magic was 0x%04lX.\n", dos.e_lfanew);

        if (dos.e_magic != IMAGE_DOS_SIGNATURE)
        {
            printf("exebits: error: e_magic of file '%s' was not IMAGE_DOS_SIGNATURE.\n", file);
            break;
        }

        if (!dos.e_lfanew)
        {
            real_bits = 16;
            break;
        }

        if (verbose)
            printf("exebits: dos.e_lfanew was 0x%08lX.\n", dos.e_lfanew);

        if (fseek(fp, dos.e_lfanew, SEEK_SET) != 0)
        {
            printf("exebits: error: Unable to read file '%s'.\n", file);
            break;
        }

        if (!fread(&Signature, sizeof(Signature), 1, fp))
        {
            printf("exebits: error: Unable to read nt signature of file '%s'.\n", file);
            break;
        }

        if (Signature != IMAGE_NT_SIGNATURE)
        {
            printf("exebits: error: nt signature of file '%s' was '0x%08lX'.\n", file, Signature);
            break;
        }

        if (!fread(&coff, sizeof(coff), 1, fp))
        {
            printf("exebits: error: Unable to read coff of file '%s'.\n", file);
            break;
        }

        switch (coff.Machine)
        {
        case IMAGE_FILE_MACHINE_UNKNOWN:
            printf("exebits: warning: unknown machine type of file '%s'.\n", file);
            break;

#define DO_MACHINE(machine, b64) \
    case machine: if (verbose) printf("exebits: %s.\n", #machine); bits64 = b64; break;
DO_MACHINE(IMAGE_FILE_MACHINE_I386, false)
DO_MACHINE(IMAGE_FILE_MACHINE_R3000, false)
DO_MACHINE(IMAGE_FILE_MACHINE_R4000, false)
DO_MACHINE(IMAGE_FILE_MACHINE_R10000, false)
DO_MACHINE(IMAGE_FILE_MACHINE_WCEMIPSV2, false)
DO_MACHINE(IMAGE_FILE_MACHINE_ALPHA, false)
DO_MACHINE(IMAGE_FILE_MACHINE_SH3, false)
DO_MACHINE(IMAGE_FILE_MACHINE_SH3DSP, false)
DO_MACHINE(IMAGE_FILE_MACHINE_SH3E, false)
DO_MACHINE(IMAGE_FILE_MACHINE_SH4, false)
DO_MACHINE(IMAGE_FILE_MACHINE_SH5, false)
DO_MACHINE(IMAGE_FILE_MACHINE_ARM, false)
DO_MACHINE(IMAGE_FILE_MACHINE_ARMNT, false)
DO_MACHINE(IMAGE_FILE_MACHINE_ARM64, true)
DO_MACHINE(IMAGE_FILE_MACHINE_THUMB, false)
DO_MACHINE(IMAGE_FILE_MACHINE_AM33, false)
DO_MACHINE(IMAGE_FILE_MACHINE_POWERPC, false)
DO_MACHINE(IMAGE_FILE_MACHINE_POWERPCFP, false)
DO_MACHINE(IMAGE_FILE_MACHINE_IA64, true)
DO_MACHINE(IMAGE_FILE_MACHINE_MIPS16, false)
DO_MACHINE(IMAGE_FILE_MACHINE_ALPHA64, true)
DO_MACHINE(IMAGE_FILE_MACHINE_MIPSFPU, false)
DO_MACHINE(IMAGE_FILE_MACHINE_MIPSFPU16, false)
DO_MACHINE(IMAGE_FILE_MACHINE_TRICORE, false)
DO_MACHINE(IMAGE_FILE_MACHINE_CEF, false)
DO_MACHINE(IMAGE_FILE_MACHINE_EBC, false)
DO_MACHINE(IMAGE_FILE_MACHINE_AMD64, true)
DO_MACHINE(IMAGE_FILE_MACHINE_M32R, false)
DO_MACHINE(IMAGE_FILE_MACHINE_CEE, false)
#undef DO_MACHINE

        default:
            printf("exebits: warning: Unknown machine type (0x%04X).\n", coff.Machine);
            break;
        }

        if (coff.Characteristics & IMAGE_FILE_DLL)
        {
            if (verbose)
                printf("exebits: IMAGE_FILE_DLL.\n");
        }

        if (coff.Characteristics & IMAGE_FILE_32BIT_MACHINE)
        {
            real_bits = 32;

            if (!fread(&opt32, sizeof(opt32), 1, fp))
            {
                printf("exebits: error: Unable to read IMAGE_OPTIONAL_HEADER32 of file '%s'.\n", file);
                break;
            }
            switch (opt32.Magic)
            {
            case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                if (verbose)
                    printf("exebits: IMAGE_NT_OPTIONAL_HDR32_MAGIC\n");
                break;
            case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                printf("exebits: error: IMAGE_NT_OPTIONAL_HDR64_MAGIC: mismatch\n");
                real_bits = 0;
                break;
            case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
                if (verbose)
                    printf("exebits: IMAGE_ROM_OPTIONAL_HDR_MAGIC\n");
                break;
            }
            if (real_bits && opt64.CheckSum)
            {
#ifdef _WIN32
                if (MapFileAndCheckSumA(file, &HeaderSum, &CheckSum) != 0)
                {
                    printf("exebits: error: CheckSum of file '%s' is invalid\n", file);
                    real_bits = 0;
                }
#endif
            }
        }

        if (bits64)
        {
            real_bits = 64;
            if (!fread(&opt64, sizeof(opt64), 1, fp))
            {
                printf("exebits: error: Unable to read IMAGE_OPTIONAL_HEADER64 of file '%s'.\n", file);
                break;
            }
            switch (opt64.Magic)
            {
            case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
                printf("exebits: error: IMAGE_NT_OPTIONAL_HDR32_MAGIC: mismatch\n");
                real_bits = 0;
                break;
            case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
                if (verbose)
                    printf("exebits: IMAGE_NT_OPTIONAL_HDR64_MAGIC\n");
                break;
            case IMAGE_ROM_OPTIONAL_HDR_MAGIC:
                if (verbose)
                    printf("exebits: IMAGE_ROM_OPTIONAL_HDR_MAGIC\n");
                break;
            }
            if (real_bits && opt64.CheckSum)
            {
#ifdef _WIN32
                if (MapFileAndCheckSumA(file, &HeaderSum, &CheckSum) != 0)
                {
                    printf("exebits: error: CheckSum of file '%s' is invalid\n", file);
                    real_bits = 0;
                }
#endif
            }
        }
    } while (0);

    if (fp)
        fclose(fp);

    switch (real_bits)
    {
    case 0:
        printf("exebits: error: '%s': Looks like invalid exe.\n", file);
        break;
    case 16:
        printf("exebits: '%s': Looks like 16-bit exe.\n", file);
        break;
    case 32:
        printf("exebits: '%s': Looks like 32-bit exe.\n", file);
        break;
    case 64:
        printf("exebits: '%s': Looks like 64-bit exe.\n", file);
        break;
    }

    if (expected_bits)
    {
        ret = (expected_bits == real_bits);
    }
    else
    {
        ret = (real_bits != 0);
    }

    return ret;
}

int main(int argc, char **argv)
{
    if (argc <= 1 || strcmp(argv[1], "--help") == 0)
    {
        show_help();
        return EXIT_SUCCESS;
    }

    if (strcmp(argv[1], "--version") == 0)
    {
        show_version();
        return EXIT_SUCCESS;
    }

    int bits = 0;
    char *your_file = NULL;
    bool verbose = false;
    for (int i = 1; i < argc; ++i)
    {
        if (strcmp(argv[i], "--verbose") == 0)
        {
            verbose = true;
        }
        else if (strcmp(argv[i], "--bits") == 0)
        {
            if (i + 1 < argc)
            {
                ++i;
                bits = atoi(argv[i]);
                switch (bits)
                {
                case 16:
                case 32:
                case 64:
                    break;
                default:
                    printf("exebits: error: bits must be 16, 32, or 64.\n");
                    return EXIT_FAILURE;
                }
            }
            else
            {
                printf("exebits: error: No argument specified for --bits.\n");
                return EXIT_FAILURE;
            }
        }
        else
        {
            if (your_file)
            {
                printf("exebits: error: You cannot specify multiple files.\n");
                return EXIT_FAILURE;
            }
            else
            {
                your_file = argv[i];
            }
        }
    }

    if (exebits(your_file, bits, verbose))
        return EXIT_SUCCESS;
    else
        return EXIT_FAILURE;
}
