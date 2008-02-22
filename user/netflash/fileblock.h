/****************************************************************************/

/*
 *	fileblock.h -- common file buffer list
 */

/****************************************************************************/
#ifndef FILEBLOCK_H
#define	FILEBLOCK_H 1
/****************************************************************************/

struct fileblock {
    unsigned char	*data;
    unsigned long	pos;
    unsigned long	length;
    unsigned long	maxlength;
    struct fileblock	*next;
};

extern struct fileblock *fileblocks;
extern unsigned int file_length;
extern unsigned int image_length;

extern void remove_data(int length);

/****************************************************************************/
#endif /* FILEBLOCK_H */
