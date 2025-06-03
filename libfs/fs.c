#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define FAT_PER_BLOCK 2048 
#define FILE_IN_ROOT 128

struct superblock {
    uint8_t signature[8];   
    uint16_t total_blocks;    
    uint16_t root_index;     
    uint16_t data_start_index;
    uint16_t data_block_count; 
    uint8_t fat_block_count;  
    uint8_t padding[4079];  
} __attribute__((packed));

struct root_file {
    char filename[16];
    uint32_t size;
    uint16_t first_index;
    uint8_t padding[10];
} __attribute__((packed));

struct mount {
	int mounted;
	struct superblock sb;
	uint16_t *FAT;
	struct root_file *root_dir;
};

struct mount disk;
static int disk_opened = 0;

static void mount_cleanup(void)
{
    if (disk.FAT)  { free(disk.FAT);  disk.FAT  = NULL; }
    if (disk.root_dir) { free(disk.root_dir); disk.root_dir = NULL; }
    if (disk_opened) {     
        block_disk_close();
        disk_opened = 0;
    }
    disk.mounted = 0;
}

void disk_init(){
    disk.FAT      = NULL;
    disk.root_dir = NULL;
    disk_opened   = 0;
    return;
}

int fs_mount(const char *diskname){
    if (disk.mounted) {
        return -1;
    }

	disk_init();

	// Open the block
	if (block_disk_open(diskname) != 0){
		// Something is wrong
        mount_cleanup();
		return -1;
	}
    disk_opened = 1;

	// Block
	// Read the super block
    if (block_read(0, &disk.sb) != 0) {
        // Something is wrong
        mount_cleanup();
		return -1;
    }

	// Read signature
	if (memcmp(disk.sb.signature, "ECS150FS", 8)){
		// Not ECS150FS system
        mount_cleanup();
		return -1;
	}

	// Read FAT
	size_t fat_bytes = (size_t)FAT_PER_BLOCK * disk.sb.fat_block_count* sizeof(uint16_t);
    disk.FAT = malloc(fat_bytes);
	if(!disk.FAT){
		// Something is wrong
        mount_cleanup();
		return -1;
	}

	for (uint8_t i = 0; i < disk.sb.fat_block_count; ++i){
		// Read FAT from block
		if (block_read(1 + i, &disk.FAT[i * FAT_PER_BLOCK]) != 0){
        	// Something is wrong
            mount_cleanup();
		    return -1;
    	}
	}

	// Read root directory
	disk.root_dir = malloc(sizeof *disk.root_dir * FILE_IN_ROOT);
	if(!disk.root_dir){
		// Something is wrong
        mount_cleanup();
		return -1;
	}

	if (block_read(disk.sb.root_index, disk.root_dir) != 0) {
		// Something is wrong
        mount_cleanup();
        return -1;
    }

    disk.mounted = 1;

	return 0;
}

int fs_umount(void)
{
    if (!disk.mounted){
        return -1;
    }

    for (uint8_t i = 0; i < disk.sb.fat_block_count; ++i)
        if (block_write(1 + i, &disk.FAT[i * FAT_PER_BLOCK]) != 0) {
            mount_cleanup();
            return -1;
        }

    if (block_write(disk.sb.root_index, disk.root_dir) != 0){
        mount_cleanup();
        return -1;
	}

    mount_cleanup();

    return 0;
}

int fs_info(void)
{
	// No mounted disk
	if (!disk.mounted){
        return -1;
	}

    uint32_t total_blk_count  = disk.sb.total_blocks;
    uint32_t fat_blk_count    = disk.sb.fat_block_count;
    uint32_t rdir_blk         = disk.sb.root_index;
    uint32_t data_blk         = disk.sb.data_start_index;
    uint32_t data_blk_count   = disk.sb.data_block_count;

    uint32_t fat_free = 0;
    for (uint32_t i = 0; i < data_blk_count; i++){
        if (disk.FAT[i] == 0){
            fat_free++;
		}
	}

    uint32_t rdir_free = 0;
    for (uint32_t i = 0; i < FILE_IN_ROOT; i++){
        if (disk.root_dir[i].filename[0] == '\0'){
            rdir_free++;
		}
	}

	// Print info
    printf("FS Info:\n");
    printf("total_blk_count=%u\n", total_blk_count);
    printf("fat_blk_count=%u\n",   fat_blk_count);
    printf("rdir_blk=%u\n",        rdir_blk);
    printf("data_blk=%u\n",        data_blk);
    printf("data_blk_count=%u\n",  data_blk_count);
    printf("fat_free_ratio=%u/%u\n",
           fat_free, data_blk_count);
    printf("rdir_free_ratio=%u/%u\n",
           rdir_free, FILE_IN_ROOT);

    return 0;
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
}

int fs_ls(void)
{
	/* TODO: Phase 2 */
}

int fs_open(const char *filename)
{
	/* TODO: Phase 3 */
}

int fs_close(int fd)
{
	/* TODO: Phase 3 */
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
}
