/*
 * Copyright (c) 2012 eMN Technologies (info@emntech.com)
 *
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <elf.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/procfs.h>

struct layout {
        void *next;
        void *return_addr;
};

int get_ebp(char *corefile, unsigned int *ebp, unsigned int *eip)
{
    Elf32_Ehdr *elfh;
    Elf32_Shdr *elfsh;
    Elf32_Phdr *elfphdr;
    char *p = NULL;
    char buf[1000], sbuf[1000];
    int ret, fd, i = 0, size;

    
    fd = open(corefile, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 0;
    }
    
    /* Read ELF header*/
    ret = read(fd, buf, sizeof(*elfh));
    if (!ret) {
        perror("Error Reading the ELF Header");
        close(fd);
        return -1;
    }
    elfh = (Elf32_Ehdr *) buf;
    /* Is it ELF*/
    if ((elfh->e_ident[0] != 0x7f) || (elfh->e_ident[1] != 'E') ||
        (elfh->e_ident[2] != 'L') || (elfh->e_ident[3] != 'F')) {
        printf("\nUnrecongised File Format");
        close(fd);
        return -1;
    }

    /*
     * read program headers and print
     */
    size = elfh->e_phnum * elfh->e_phentsize;
    p =  malloc(size);
    
    lseek(fd, elfh->e_phoff, SEEK_SET);
    ret = read(fd, p, size);
    if (ret != size) {
        printf("\nCannot read Program Header");
        close(fd);
        return -1;
    }
    elfphdr = (Elf32_Phdr *)p;
    for (i = 0; i < elfh->e_phnum; i++) {
        if (elfphdr->p_type == PT_NOTE) {
            unsigned char *pdata;
            struct note {
                unsigned int namesz;
                unsigned int descsz;
                unsigned int type;
            };
            struct note *not;
            int pad = 0;

            pdata = malloc(elfphdr->p_filesz);
            lseek(fd, elfphdr->p_offset, SEEK_SET);
            ret = read(fd, pdata, elfphdr->p_filesz);
            not = (struct note *) pdata;
            if (not->namesz % 4)
                pad  = 4 - (not->namesz % 4);
            if (not->type == NT_PRSTATUS) {
                struct elf_prstatus *prs;
                
                prs = (struct elf_prstatus *)(pdata + sizeof(*not) + not->namesz + pad);
                *ebp =  prs->pr_reg[5];
                *eip = prs->pr_reg[12];
            }
        }
        elfphdr++;
    }
    free(p);        
    close(fd);
    return 0;
}

int print_syms(unsigned int symaddr, char *symbolfile)
{
    FILE *fp;
    int fd, ret, i;
    char buf[300] = { 0 };
    unsigned int addr = 0, nextaddr;

    char symbol[40], nxtsymbol[40], type;

    fp = fopen(symbolfile, "r");
    if (!fp) {
        printf("Error");
        return 0;
    }
    
    while (fgets(buf, 300, fp)) {
        sscanf(buf, "%x %c %s", &addr, &type, symbol);
        if (!addr)
            continue;

        if (symaddr >= addr) {
            /*
             * find next symbol
             */
            int foff = ftell(fp);
            if (fgets(buf, 300, fp)) {
                sscanf(buf, "%x %c %s", &nextaddr, &type,
                       nxtsymbol);
                if (symaddr <= nextaddr) {
                    /*
                     * We found the range, print the symbol
                     */
                    printf("\n0x%x %s+0x%x", symaddr,
                           symbol, symaddr - addr);
                    break;
                }
            }
            fseek(fp, foff, SEEK_SET);
        }
    }
    fclose(fp);
}


void btrace(char *symfile, int depth, int withsyms, unsigned eip, unsigned int ebp, void *data)
{
        struct layout *lay;
        int i;
    unsigned int nextebp = ebp;

        lay = (struct layout *) data;
    
    if (eip) {  // print current instruction
        if (withsyms)
            print_syms((unsigned int)eip, symfile);
        else
            printf("%x\n", eip);
    }

        for (i = 0; i < depth; i++) {
        ebp = nextebp;

        if (withsyms)
            print_syms((unsigned int)lay->return_addr, symfile);
        else
            printf("%p\n", lay->return_addr);

        nextebp = (unsigned int) lay->next;
        lay = (struct layout *) (data + (nextebp - ebp));
        }
        printf("\n");
}


int main (int argc, char **arg)
{
    Elf32_Ehdr *elfh;
    Elf32_Shdr *elfsh;
    Elf32_Phdr *elfphdr;
    unsigned int ebp, eip;
    char *p = NULL;
    char buf[1000], sbuf[1000];
    int ret, fd, i = 0, size;
    char *symfile = NULL;
    int depth = 2; //default depth

    if (argc < 2) {
        printf("\nUsage: coretrace <core> [symbolfile]\n");
        return 0;
    }

    ret = get_ebp(arg[1], &ebp, &eip);    
    if (ret < 0) {
        printf("\nCannot read EBP value\n");
        return 0;
    }
    fd = open(arg[1], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 0;
    }
    
    /* Read ELF header*/
    ret = read(fd, buf, sizeof(*elfh));
    if (!ret) {
        perror("Error Reading the ELF Header");
        goto cl;
    }
    elfh = (Elf32_Ehdr *) buf;
    /* Is it ELF*/
    if ((elfh->e_ident[0] != 0x7f) || (elfh->e_ident[1] != 'E') ||
        (elfh->e_ident[2] != 'L') || (elfh->e_ident[3] != 'F')) {
        printf("\nUnrecongised File Format");
        goto cl;
    }

    /*
     * read program headers and print
     */
    size = elfh->e_phnum * elfh->e_phentsize;
    p =  malloc(size);
    
    lseek(fd, elfh->e_phoff, SEEK_SET);
    ret = read(fd, p, size);
    if (ret != size) {
        printf("\nCannot read Program Header");
        goto cl;
    }
    elfphdr = (Elf32_Phdr *)p;
    for (i = 0; i < elfh->e_phnum; i++) {
        if (elfphdr->p_type == PT_LOAD) {
            unsigned char *pdata, *temp;
            unsigned int addr, endaddr;
            int j;

            pdata = malloc(elfphdr->p_filesz);
            lseek(fd, elfphdr->p_offset, SEEK_SET);
            ret = read(fd, pdata, elfphdr->p_filesz);
            addr = elfphdr->p_vaddr;
            endaddr = elfphdr->p_vaddr + elfphdr->p_filesz;
            if ((ebp > addr) && (ebp < endaddr)) { // we have got stack segment
                temp = pdata + (ebp - addr);
                if (arg[2])  // we have symbol file given*/
                    btrace(arg[2], depth, 1, eip, ebp, temp);
                else            
                    btrace(NULL, depth, 0, eip, ebp, temp);
                free(pdata);
                break; // we are done
            }
            free(pdata);
        }
        elfphdr++;
    }
    free(p);        

cl:    
    close(fd);
    
    return 0;
}