#ifndef _ASM_SWIOTLB_H
#define _ASM_SWIOTLB_H 1

/* SWIOTLB interface */

extern dma_addr_t swiotlb_map_single(struct device *hwdev, void *ptr, size_t size,
				      int dir);
extern void swiotlb_unmap_single(struct device *hwdev, dma_addr_t dev_addr,
				  size_t size, int dir);
extern void swiotlb_sync_single_for_cpu(struct device *hwdev,
					 dma_addr_t dev_addr,
					 size_t size, int dir);
extern void swiotlb_sync_single_for_device(struct device *hwdev,
					    dma_addr_t dev_addr,
					    size_t size, int dir);
extern void swiotlb_sync_sg_for_cpu(struct device *hwdev,
				     struct scatterlist *sg, int nelems,
				     int dir);
extern void swiotlb_sync_sg_for_device(struct device *hwdev,
					struct scatterlist *sg, int nelems,
					int dir);
extern int swiotlb_map_sg(struct device *hwdev, struct scatterlist *sg,
		      int nents, int direction);
extern void swiotlb_unmap_sg(struct device *hwdev, struct scatterlist *sg,
			 int nents, int direction);
extern int swiotlb_dma_mapping_error(dma_addr_t dma_addr);
extern dma_addr_t swiotlb_map_page(struct device *hwdev, struct page *page,
                                   unsigned long offset, size_t size,
                                   enum dma_data_direction direction);
extern void swiotlb_unmap_page(struct device *hwdev, dma_addr_t dma_address,
                               size_t size, enum dma_data_direction direction);
extern int swiotlb_dma_supported(struct device *hwdev, u64 mask);
extern void swiotlb_init(void);

#ifdef CONFIG_SWIOTLB
extern int swiotlb;
#else
#define swiotlb 0
#endif

#endif
