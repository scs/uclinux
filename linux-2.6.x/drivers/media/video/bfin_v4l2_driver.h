/* This structure is meant to store
 * per device info. Instances of this
 * structure shall represent diffrent
 * devices(capture, out etc.)
 */
struct bfin_v4l2 {
	struct video_device *videodev ;
	struct semaphore resource_lock;	/* prevent evil stuff */
	u8 initialized;		/* flag if device has been correctly initalized */
	int user;		/* number of current users */
	unsigned short id;	/* number of this device */
	char name[32];		/* name of this device */
	unsigned char revision;	/* revision of bfin_v4l2_driver */
	unsigned char *bfin_v4l2_mem;	/* pointer to mapped IO memory */
};


/* Structure to store per open info.
 * private_data member of file struct
 * that is passed by calling application
 * shall get set to an instance of
 * this structure
 */

struct bfin_v4l2_fh {			
	struct bfin_v4l2 *bfn;
	char * buffer ;
	u8 write_flag ;
	u8 read_flag ;
} ;
