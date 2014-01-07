#ifndef XC_SAVE_RESTORE_COLO_H
#define XC_SAVE_RESTORE_COLO_H

#include <sys/time.h>

#include <xg_save_restore.h>
#include <xg_private.h>

extern int restore_colo_init(struct restore_data *, void **);
extern void restore_colo_free(struct restore_data *, void *);
extern char* get_page(struct restore_data *, void *, unsigned long);
extern int flush_memory(struct restore_data *, void *);
extern int colo_hvm_clear_page(struct restore_data *, void *, unsigned long pfn);
extern int update_p2m_table(struct restore_data *, void *);
extern int finish_colo(struct restore_data *, void *);
extern int colo_wait_checkpoint(struct restore_data *, void *);

/*
** During (live) save/migrate, we maintain a number of bitmaps to track
** which pages we have to send, to fixup, and to skip.
*/

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define BITS_TO_LONGS(bits) (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define BITMAP_SIZE   (BITS_TO_LONGS(dinfo->p2m_size) * sizeof(unsigned long))

#define BITMAP_ENTRY(_nr,_bmap) \
   ((volatile unsigned long *)(_bmap))[(_nr)/BITS_PER_LONG]

#define BITMAP_SHIFT(_nr) ((_nr) % BITS_PER_LONG)

#define ORDER_LONG (sizeof(unsigned long) == 4 ? 5 : 6)

static inline int test_bit (int nr, volatile void * addr)
{
    return (BITMAP_ENTRY(nr, addr) >> BITMAP_SHIFT(nr)) & 1;
}

static inline void clear_bit (int nr, volatile void * addr)
{
    BITMAP_ENTRY(nr, addr) &= ~(1UL << BITMAP_SHIFT(nr));
}

static inline void set_bit ( int nr, volatile void * addr)
{
    BITMAP_ENTRY(nr, addr) |= (1UL << BITMAP_SHIFT(nr));
}

static inline void colo_output_log(FILE *file, const char *fmt, ...)
{
    va_list ap;
    struct timeval tv;

    gettimeofday(&tv, NULL);
    fprintf(file, "[%lu.%06lu]", tv.tv_sec, tv.tv_usec);
    va_start(ap, fmt);
    vfprintf(file, fmt, ap);
    fflush(file);
    va_end(ap);
}
#endif
