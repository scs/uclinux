/*
 * dagrab.c for dagrab
 *
 * DAGRAB - dumps digital audio from cdrom to riff wave files
 *
 * (C) 2000 Marcello Urbani <marcello@lumetel.it>
 * Miroslav Stibor <stibor@vertigo.fme.vutbr.cz>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <getopt.h>
#include <sys/timeb.h>

#ifdef PTHREAD
#include <pthread.h>
#endif

#define __need_timeval		/* needed by glibc */
#include <time.h>
#include <linux/cdrom.h>

#ifdef USE_UCDROM
#include <linux/ucdrom.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/vfs.h>

#include "main.h"
#include "const.h"
#include "jit_in.h"
#include "jitter.h"
#include "cddb.h"
#include "print.h"
#include "err.h"
#include "version.h"

static int cdrom_fd;
char *PROGNAME;
char trackname[BLEN + 1] = "";
int opt_blocks = N_BUF;
int overlap = OVERLAP;
static int opt_blocks0 = N_BUF;
static int opt_bufstep;
static int opt_chmod = 0660;
static unsigned opt_srate = 44100;	/* still unused */
static char opt_spchk;
char opt_jitter_in = 0;
char opt_dumb = 0;
char opt_verbose = 0;
char opt_stdout = 0;
char opt_filter = 0;
int opt_delta = DELTA;
int opt_bufsize;
int opt_bufsize0;
int opt_speed = MAX_SPEED;
int opt_speed0 = MAX_SPEED;
static int opt_examples = 0;

#ifdef DEBUG
int opt_debug = 0;
#endif

static char opt_name = 0;	/* use cddb name for wavs */
char opt_save = 0;		/* save cddb info */
char opt_cddb = 0;
char *opt_cddb_path = NULL;
char *opt_cddb_host = CDDB_HOST;
int opt_cddb_port = CDDB_PORT;

typedef struct {
	char *nam;
	FILE *file;
	Buffer buffer;
#ifdef PTHREAD
	int pipe[2][2];
	FILE *f[2][2];
#endif
} thread_args;

thread_args t_args;
#define threaded (t_args.pipe[1][1])

kword kwords[] = {
	{"@YER", KW_YEAR, "Year", 			"YEAR:  "},
	{"@GNR", KW_GNR, "Genre", 			"GENRE: "},
	{"@DIS", KW_DISK, "Disk name (guessed)",	"TITLE: "},
	{"@NUM", KW_NUM, "Track number", ""},
	{"@AUT", KW_AUTHOR, "Disk author (guessed)",	"AUTHOR:"},
	{"@FDS", KW_FULLD, "Full disk name (usually author/title)", ""},
	{"@TRK", KW_TRACK, "Track name", ""}
}, *kwords_p;


Wavefile cd_newave(unsigned size)
{
	Wavefile dummy = {
		{'R', 'I', 'F', 'F'}, 0x24 + (size *= CD_FRAMESIZE_RAW),
		{'W', 'A', 'V', 'E'},
		{'f', 'm', 't', ' '}, 0x10, 1, 2, 44100, 4 * 44100, 4, 16,
		{'d', 'a', 't', 'a'}, size
	};
/* dummy.Dlen=size;
   dummy.Rlen=0x24+size; */
	dummy.sample_rate = opt_srate;
	dummy.channel = 2;
	dummy.byte_rate = opt_srate << dummy.channel;
	dummy.align = dummy.channel * dummy.sample >> 3;
	return dummy;
}

#define cd_get_tochdr(Th) ioctl(cdrom_fd, CDROMREADTOCHDR, Th)

int cd_get_tocentry(int trk, struct cdrom_tocentry *Te, int mode)
{
	Te->cdte_track = trk;
	Te->cdte_format = mode;
	return ioctl(cdrom_fd, CDROMREADTOCENTRY, Te);
}

void setting_grabbing(void)
{
	opt_bufsize0 = CD_FRAMESIZE_RAW * opt_blocks0;
	opt_bufsize = CD_FRAMESIZE_RAW * opt_blocks;
	opt_bufstep = opt_blocks - overlap;
}

int is_end_of_track(int *lba, int lba_end, Buffer * buf_prev,
		    Buffer * buf_acct, int *first)
{
	/*
	 * if it fails on the end of the track, we can end with reading,
	 * so we test, if there was only clear silence (0 0 0 0 0 0...)
	 *
	 * perhaps about 3 s from the end:
	 */
	char *prev_buffer = buf_prev->buffer + buf_prev->size -
	    2 * CD_FRAMESIZE_RAW;
	if (buf_prev->size && *first && (lba_end - *lba) < 400) {
		int k, l = 100000, step = 1;
		(*first)--;
		/* first look for all bytes, next test only highers */
		if (!*first)
			step = 2;

		for (k = 2 * CD_FRAMESIZE_RAW - 1; k > 0 && l > 0;
		     k -= step, l -= step)
			/* test if it is end: */
			if ((char) *(prev_buffer + k) == (char) 0) {
			} else if ((char) *(prev_buffer + k) ==
				   (char) (-1)) {
			} else
				return KO;
		/* It was probably the end of the track.. */
		*lba = lba_end;
		buf_acct->size = 0;
		dagrab_stderr("\nIt seems to be the end of the track\n");
		return OK;
	}
	return KO;
}

/* returns 1 if KEY of ripped block is not unique -- ends with 
   00 00 00 00.. or ff ff ff ff.. */
int nulls(char *buffer, int bufsize)
{
	int i;
#if 1
	char c = buffer[bufsize - 1];

	for (i = KEYLEN * 4; i > 0; i--)
		if (buffer[bufsize - i] != c)
			return 0;
#else
	int size = bufsize / 4;
	int c = ((int*) buffer)[size - 1];

	for (i = KEYLEN; i > 0; i--)
		if (((int *) (buffer))[size - i] != c)
			return 0;
#endif
	return 1;
}

int cd_read_audio(int *lba, int num, Buffer * buf_act, int begin_track,
		  Buffer * buf_prev, int lba_end)
{
	struct cdrom_read_audio ra;
	int retry = 0, err, first = 2, lba_in = *lba, moved_times = 0;
	static long int read_in_line_wo_err1 = 0;
	static long int read_in_line_wo_err2 = 0;

	ra.addr_format = CDROM_LBA;
	ra.buf = buf_act->buffer;
	ra.addr.lba = *lba;
	ra.nframes = num;
	view_status(ID_BLOCKS, lba);

      read_again:
#ifdef DEBUG
	if (opt_debug)
		printf("To read: lba = %i, num = %i\n", *lba, num);
#endif

	/* can we go to larger blocks? */
	if (read_in_line_wo_err1 > opt_blocks) {
		if (opt_blocks * 2 <= opt_blocks0 &&
		    opt_blocks * 2 + *lba < lba_end) {
			ra.nframes = opt_blocks *= 2;
			setting_grabbing();
			view_status(ID_SECTORS, &opt_blocks);
			read_in_line_wo_err1 = 0;
		}
	}
	do {
		err = ioctl(cdrom_fd, CDROMREADAUDIO, &ra);
		/* we cant read so going to smaller blocks */
		if (err && (opt_blocks / 2 >= overlap + 3)
		    && (retry == 2 || begin_track)) {
			ra.addr.lba = *lba = lba_in;	/* Move posit. */
			moved_times = 0;
			if (opt_blocks / 2 + *lba < lba_end) {
				ra.nframes = opt_blocks /= 2;
				setting_grabbing();
				view_status(ID_SECTORS, &opt_blocks);
			}
		}
		if (err && opt_speed >= 2 && (retry >= 2 || begin_track)) {
			/* we cant read so go to lower speed */
			ioctl(cdrom_fd, CDROM_SELECT_SPEED, --opt_speed);
			view_status(ID_REALSPEED, &opt_speed);
		}
		if (err && (retry < RETRYS)) {
			retry++;
			view_status(ID_BADDATA, &retry);
			retry--;
			read_in_line_wo_err1 = read_in_line_wo_err2 = 0;
		}
	} while (err && (retry++ <= RETRYS));

	buf_act->size = opt_bufsize;

	if (!err) {		/* succesfull reading */
		int c = 0;
		/* If keylen is not unique, try to find unique one. If not
		   even found, remove at least overlap area (suppose to be
		   one block wide) */
		while (!opt_dumb && ra.nframes + *lba < lba_end && 
			nulls(buf_act->buffer, buf_act->size) && c < CD_FRAMESIZE_RAW) {
				buf_act->size -= KEYLEN * 4;
				c += KEYLEN * 4;
#ifdef DEBUG	
				if (opt_debug)
					printf("nulls %i\n", CD_FRAMESIZE_RAW - c);
#endif
		}
		view_status(ID_BADDATA, &(V_STAT[NUL]));
		read_in_line_wo_err1 += opt_blocks;
		read_in_line_wo_err2 += opt_blocks;
		/* should we go to higher speed? */
		if (read_in_line_wo_err2 > 48 + opt_blocks) {
			if (opt_speed < MAX_SPEED - 1) {
				ioctl(cdrom_fd, CDROM_SELECT_SPEED,
				      ++opt_speed);
				view_status(ID_REALSPEED, &opt_speed);
			}
			read_in_line_wo_err2 = 0;
		}
#ifdef DEBUG
		if (opt_debug)
			printf
			    ("OK read: lba = %i, num = %i (opt_blocks = %i)\n",
			     ra.addr.lba, ra.nframes, opt_blocks);
#endif
		return OK;
	}			/* else: we can't reach data anyway */
	if ((opt_blocks / 2 < overlap + 3) && retry > RETRYS
	    && moved_times > 4) {
		dagrab_stderr("\nread raw ioctl repeatly failed at lba %d length %d, giving up\n",
			*lba, num < opt_blocks ? num : opt_blocks);
		return KO;
	}
	/*
	 * If we can't reach it, move back 3 times about 1/4 of block.
	 */
	if (!begin_track)
		ra.addr.lba = (*(lba) -= opt_blocks / 4);	/* Moving back */
	moved_times++;
	view_status(ID_BLOCKS, lba);

	if (is_end_of_track(lba, lba_end, buf_prev, buf_act, &first) == OK)
		return OK;

	retry = 0;
	if (moved_times > 3) {
		/*
		 * if it fails on the end of the track, we could
		 * end with reading
		 */
		if (is_end_of_track
		    (lba, lba_end, buf_prev, buf_act, &first) == OK)
			return OK;
		if (!begin_track)
			ra.addr.lba = *lba += opt_blocks / 4;	/* Move posit. */
	}
	goto read_again;
}

/* function taken from the paranoia srcs */
void FixupTOC(cd_trk_list * tl)
{
	int j;
	struct cdrom_multisession ms_str;

	ms_str.addr_format = CDROM_LBA;
	if (ioctl(cdrom_fd, CDROMMULTISESSION, &ms_str) == -1)
		return;

	/* This is an odd little piece of code --Monty
	 * believe the multisession offset :-) 
	 * adjust end of last audio track to be in the first session */
	if (ms_str.addr.lba > 100)
		for (j = tl->max; j >= tl->min; j--) {
			if (j && tl->types[j] != CDROM_DATA_TRACK &&
			    tl->types[j - 1] == CDROM_DATA_TRACK) {
				if (tl->starts[j - 1] >
				    ms_str.addr.lba - 11400)
					tl->starts[j - 1] =
					    ms_str.addr.lba - 11400;
				break;
			}
		}
}

int cd_getinfo(char *cd_dev, cd_trk_list * tl)
{
	int i;
	struct cdrom_tochdr Th;
	struct cdrom_tocentry Te;

	if ((cdrom_fd = open(cd_dev, O_RDONLY | O_NONBLOCK)) == -1)
		die(ERR_DEV_OPEN, cd_dev);

	if (cd_get_tochdr(&Th))
		die(ERR_READ_TOC, cd_dev);

	tl->min = Th.cdth_trk0;
	tl->max = Th.cdth_trk1;
	if ((tl->starts =
	     (int *) malloc((tl->max - tl->min + 1) * sizeof(int))) ==
	    NULL)
		die(ERR_ALLOC, NULL);

	if ((tl->types = (char *) malloc(tl->max - tl->min + 2)) == NULL)
		die(ERR_ALLOC, NULL);

	for (i = tl->min; i <= tl->max; i++) {
		if (cd_get_tocentry(i, &Te, CDROM_LBA))
			die(ERR_TOC_ENTRY, NULL);

		tl->starts[i - tl->min] = Te.cdte_addr.lba;
		tl->types[i - tl->min] = Te.cdte_ctrl & CDROM_DATA_TRACK;
	}
	i = CDROM_LEADOUT;
	if (cd_get_tocentry(i, &Te, CDROM_LBA))
		die(ERR_TOC_ENTRY, NULL);

	FixupTOC(tl);

	tl->starts[tl->max - tl->min + 1] = Te.cdte_addr.lba;
	tl->types[tl->max - tl->min + 1] = Te.cdte_ctrl & CDROM_DATA_TRACK;
	if (opt_cddb) {
		i = cddb_main(tl);
		if (i) {
			dagrab_stderr("error retrieving cddb data\n");
			opt_save = opt_name = opt_cddb = 0;
			strcpy(trackname, "track%02d.wav");
		/*	tl->cddb = NULL;
			tl->gnr = NULL; */
		}
		/*if (i == 1)
			tl->gnr = NULL;*/
	}

	return 0;
}

int check_for_space(char *path, unsigned int space)
{
	struct statfs buffs;
	struct stat buf;

	if (!stat(path, &buf) && !statfs(path, &buffs) &&
	    (buffs.f_bavail * buf.st_blksize) >= space)
		return 1;
	return 0;
}

inline void cd_track_name(char *name, cd_trk_list * tl, int tn,
			  char *trackname)
{
	if (opt_cddb)
		ExpandTempl(name, trackname, tn, tl, TRUE);
	else
		snprintf(name, BLEN, trackname, tn);
}

#ifdef PTHREAD
void done(int which)	/* thread done */
{
	if (threaded) {
		fputc('\n', t_args.f[which][1]);
		fflush(t_args.f[which][1]);
	}
}

void wait_for(int which)
{
	if (threaded)
		fgetc(t_args.f[which][0]);
}
#endif

void *thread_save(void *dummy)
{
#ifdef PTHREAD
	do {	/* infinite loop */
		wait_for(MAIN);
#endif
		if (t_args.buffer.size == 0)
			goto save_return;

		if (opt_jitter_in)	/* go through the jitter filter */
			jitter_in(t_args.buffer.buffer,
				  t_args.buffer.size, opt_delta);
		if (fwrite(t_args.buffer.buffer,
			   t_args.buffer.size,
			   1, t_args.file) == 0)
			die(ERR_WRITING, t_args.nam);

	      save_return:
		free(t_args.buffer.orig);
#ifdef PTHREAD
		done(THREAD);
	} while (threaded);
#endif
	return 0;
}

int cd_read_track(char *trackname, int tn, cd_trk_list * tl, char *filter,
			int std_length)
{
	Wavefile header;
	static Buffer buf_prev, buf_act, buf_1B;
	static char *buf_key = NULL, first_header = 1;
	char nam[BLEN + 1], exec_name[2 * BLEN], exec[BLEN + 1],
	    trk_pos = TRK_BEGIN, byte_shifted = NO;
	int bytes, i, shift = 0, speed = 0,
	    lba_next, lba_just, bcount, length;
	unsigned int space;
	struct timeb fsc;
	FILE *file = stdout;

	ioctl(cdrom_fd, CDROM_SELECT_SPEED, opt_speed = opt_speed0);

	/* ioctl(cdrom_fd, CDROM_SELECT_SPEED, opt_speed < opt_speed0 / 3 ?
	   opt_speed = opt_speed0 : opt_speed);
	 */
	opt_blocks = opt_blocks0;
	setting_grabbing();

	space =
	    ((tl->starts[tn - tl->min + 1] - tl->starts[tn - tl->min]) *
	     CD_FRAMESIZE_RAW);

	cd_track_name(nam, tl, tn, trackname);
	if (filter[0]) {
		snprintf(exec, BLEN, filter, nam, nam, nam, nam, nam,
			 nam, nam);
		if (!opt_cddb)
			TerminateTempl(exec);
		else
			ExpandTempl(exec_name, exec, tn, tl, FALSE);
	}

	if (tl->types[tn - tl->min]) {
		dagrab_stderr("Track %d is not an audio track\n", tn);
		return 1;
	} else if (opt_verbose)
		fprintf(stderr,
			"%s%c(lba %d to %d, %d MB)\n",
			nam, strlen(nam) >= 50 ? '\n' : ' ',
			tl->starts[tn - tl->min],
			tl->starts[tn - tl->min + 1] - 1, space >> 20);
	tn -= tl->min;

	if (!opt_stdout) {
		if (!(file = fopen(nam, "w")))
			die(ERR_OPEN, nam);
		if (chmod(nam, opt_chmod) == -1)
			die(ERR_CHMOD, nam);
		if (opt_spchk && !check_for_space(nam, space)) {
			fclose(file);
			unlink(nam);
			dagrab_stderr("Not enough free space on disk for track %d\n",
				tn + tl->min);
			return 1;
		}
	}

	if (!buf_key) {
		buf_key = (char *) malloc(KEYLEN * sizeof(int));
		buf_prev.buffer = (char *) malloc(CD_FRAMESIZE_RAW * 2);
	}

	buf_act.orig = buf_act.buffer = (char *) malloc(opt_bufsize0);

	if (!buf_act.buffer || !buf_key || !buf_prev.buffer)
		die(ERR_ALLOC, NULL);

	buf_prev.size = buf_1B.size = 0;
	buf_1B.buffer = NULL;

	t_args.file = file;
	t_args.nam = nam;

	lba_just = tl->starts[tn];
	lba_next = tl->starts[tn + 1];
	length = lba_next - lba_just;

	header = cd_newave(opt_stdout ? std_length : length);
	if (!opt_stdout || first_header) {
		if (fwrite(&header, sizeof(header), 1, file) == 0)
			die(ERR_WRITING, nam);
		first_header = 0;
	}

	if (opt_verbose)
		printf
		    ("lba read                          spd     sect.  overl. retry jitter  est. time\n");
	view_status(ID_NULL, NULL);
	view_status(ID_SECTORS, &opt_blocks);
	view_status(ID_REALSPEED, &opt_speed);
	/* main loop */
	bytes = 0;
	bcount = 0;

#ifdef PTHREAD
	done(THREAD);	/* mark thread for first using */
#endif
	ftime(&fsc);
	if (cd_read_audio	/* see TRK_BEGIN below */
	    (&lba_just, opt_blocks, &buf_act, 1, &buf_prev,
	     lba_next) == KO)
		goto close_errs;

	for (i = lba_just; i < lba_next; i += opt_bufstep) {
		int perc, q, overlap_old, sc;
		struct timeb fsc_now;
		float sp;

		if (bcount) {
			ftime(&fsc_now);
			if ((sc = 1000 * (fsc_now.time - fsc.time) + fsc_now.millitm - fsc.millitm))
				speed = 1000 * bcount / sc;
		}

		bcount = i - lba_just + opt_bufstep;
		if (trk_pos == TRK_BEGIN)
			goto was_first;

		if (opt_verbose) {
			perc = 100 * (i - lba_just) / length;
			sp = (float) speed / 75;
			/* Note: ID_PERC and ID_MISSING does not refresh
			   status view */
			view_status(ID_PERC, &perc);
			if (speed > 0) {
				int missing = (lba_next - i) / speed;
				view_status(ID_MISSING, resttime(missing));
			}
			view_status(ID_SPEED, &sp);
		}
		q = 0;
		overlap_old = overlap;
		if (NULL == (buf_act.orig = buf_act.buffer =
			     (char *) malloc(opt_bufsize0)))
			die(ERR_ALLOC, NULL);
		do {
			i -= /* ie. 4 - 2 */ overlap - overlap_old;
			/* overlap changes in jitter() */
			overlap_old = overlap;
			if (i > lba_next)
				break;
			if (cd_read_audio(&i,
					  i + opt_blocks < lba_next ?
					  opt_blocks : lba_next - i,
					  &buf_act, 0, &buf_prev,
					  lba_next) == KO)
				goto close_errs;

			if (!buf_act.size) {
				free(buf_act.orig);
				goto close_it;
			}
#if DEBUG
			if (opt_debug && q)
				printf("Jitter loop: retry = %i\n", q);
#endif
		} while (((shift = jitter(&buf_act, buf_key, q)) == -1)
			 && (q++ < RETRYS_O));
		/******************************************************** 
		 * Here ends ripping.					*
		 * Note: jitter_in() proceeds in cd_read_audio()	*
		 ********************************************************/
	      was_first:
		/********************************************************
		 * Could it be the end of the track (when overlap err)?	*
		 ********************************************************/
		if (shift == -1) {
			/* If it's only 1 s from the end, let it be.. */
			if (i + 70 > lba_next) {
				dagrab_stderr(
					"\nHope it is the end of the track\n");
				free(buf_act.orig);
				goto close_it;
			}
			/* End on overlap error */
			dagrab_stderr("\njitter overlap error near block %d, skipping\n\n",
				i);
		      close_errs:
			/* Can't read data */
			if (!opt_stdout)
				fclose(file);
			free(buf_act.orig);
			return 1;
		}
		/********************************************************
		 * How many samples ripped:				*
		 ********************************************************/
		/* (write the overlap area always next time,
		 * except the last bytes (TRK_END) -- see below) */
		if (!opt_dumb)
			buf_act.size -= shift + KEYLEN * sizeof(int);

		buf_act.buffer += shift;
		/*
		 * What we set for overlap area next time?
		 */
		overlap -= shift / CD_FRAMESIZE_RAW;
		if (overlap < OVERLAP && !opt_dumb)
			overlap = OVERLAP;
		/* Note: overlap does not refresh status view */
		view_status(ID_OVERLAP, &overlap);
		view_status(ID_OVERLAP, &(V_STAT[OVERLAP_OK]));
		setting_grabbing();
		/********************************************************
		 * Last bytes						*
		 ********************************************************/
#if DEBUG
		if (opt_debug)
			printf("Now is to save %i B\n", bytes + buf_act.size + (int) (KEYLEN * sizeof(int)));
#endif
		if (bytes + buf_act.size + (int) (KEYLEN * sizeof(int))
		    >= length * CD_FRAMESIZE_RAW) {
			trk_pos = TRK_END;
			/* close wav with correct size */
			buf_act.size = length * CD_FRAMESIZE_RAW - bytes;
		}
		bytes += buf_act.size;
		/********************************************************
		 * Copy the end of the tail of the previous ripping and	*
		 * make jitter corr. on this part (just only the edges)	*
		 ********************************************************/
		if (trk_pos != TRK_BEGIN && !opt_dumb) {
			memcpy(buf_act.buffer, buf_key,
			       KEYLEN * sizeof(int) - 8);
			if (opt_jitter_in)
				jitter_in(buf_act.buffer +
					  KEYLEN * sizeof(int) - 8, 24,
					  opt_delta);
		} else if (trk_pos != TRK_END)
			trk_pos = TRK_INSIDE;

		if (bytes == length * CD_FRAMESIZE_RAW) {
			i = lba_next;
			goto just_write;
		}
		/********************************************************
		 * Make a copy of the tail 				*
		 ********************************************************/
		memcpy(buf_key, buf_act.buffer + buf_act.size,
		       KEYLEN * sizeof(int));

		/********************************************************
		 * Make a copy of ripped sectors if near the end	*
		 ********************************************************/
		if (i + 500 > lba_next) /* see is_end_of_track() */
			memcpy(buf_prev.buffer, buf_act.buffer +
			       buf_act.size - 2 * CD_FRAMESIZE_RAW,
			       buf_prev.size = 2 * CD_FRAMESIZE_RAW);

		if (!opt_dumb && nulls(buf_key, KEYLEN * sizeof(int)) && trk_pos != TRK_END) {
#ifdef DEBUG
			if (byte_shifted != NO && opt_debug)
				puts("nulls in main loop");
#endif
			/* Because we lost the key, test for 1 byte shift */
			byte_shifted = NO;
		}
		/********************************************************
		 * Do we need 1 B correcting? (only on the beginning)	*
		 ********************************************************/
		if (byte_shifted == NO && !opt_dumb) {
			int ret;
			if (NULL == (buf_1B.buffer = (char *)
				     realloc(buf_1B.buffer,
					     buf_act.size + buf_1B.size +
					     KEYLEN * sizeof(int))))
				die(ERR_ALLOC, NULL);

			memcpy(buf_1B.buffer + buf_1B.size, buf_act.buffer,
			       buf_act.size + KEYLEN * sizeof(int));
			buf_1B.size += buf_act.size;
			ret = need_1B_shift(&buf_1B, trk_pos);
			if (ret == YES) {	/* done, do write */
				memmove(buf_1B.buffer + 1, buf_1B.buffer,
					buf_1B.size - 1 +
					KEYLEN * sizeof(int));
				buf_1B.buffer[0] = 0;
				byte_shifted = YES;
			}
			if (ret == NO)
				byte_shifted = YES;	/* done, do write */

			free(buf_act.orig);

			if (ret == DONTKNOW && trk_pos != TRK_END)	/* (we will have other try) */
				goto do_not_write_now;

			buf_act.orig = buf_act.buffer = buf_1B.buffer;
			buf_act.size = buf_1B.size;
			buf_1B.buffer = NULL;
			buf_1B.size = 0;
		} 
	      just_write:
#ifdef PTHREAD
		wait_for(THREAD);
#endif
		t_args.buffer = buf_act;
#ifdef PTHREAD
		done(MAIN);
		if (!threaded)
			thread_save(NULL);
#else
		thread_save(NULL);
#endif
	      do_not_write_now:
		;
	}
	/****************************************************************
	 * Close output file 						*
	 ****************************************************************/
      close_it:
#ifdef PTHREAD
	wait_for(THREAD);
#endif
	if (!opt_stdout)
		fclose(file);

	i = view_status(ID_OVERLAP, &(V_STAT[NUL]));
	{
		char buf[20] = "                    ";
		length = 80 - fprintf(stderr, "%s: Track %d dumped at %.2fx speed in %s, ",
			PROGNAME, tn + tl->min, (float) speed / 75,
			resttime(bcount / speed));
		length -= fprintf(stderr, opt_jitter_in ?
			"%i jitter correction%c" :
			"jitter corrections off", i,
			i == 1 ? ' ' : 's');
		buf[length > 0 ? length : 0] = 0;
		fprintf(stderr, "%s\n\n", buf);
	}

	if (filter[0])
		system(opt_cddb ? exec_name : exec);
	return 0;
}

/* expands 3-7 to { 3; 4; 5; 6; 7 }*/
int add_to_tr_list(char *s, int *tr_list, cd_trk_list * tl)
{
	int j, k, tmp;
	char *p;

	if ((p = strchr(s, '-'))) {
		j = atoi(s);
		k = atoi(p + 1);
		if (j > k) {
			k ^= j;
			j ^= k;
			k ^= j;
		}
		for (tmp = j; tmp <= k; tmp++)
			if (tmp >= tl->min && tmp <= tl->max)
				tr_list[tmp] = 1;
	} else {
		if (strcmp("all", s) == 0)
			return 1;
		tmp = atoi(s);
		if (tmp >= tl->min && tmp <= tl->max)
			tr_list[tmp] = 1;
	}
	return 0;
}

/* expands host:port to 'char *host', 'int port' */
void set_cddb(char *optarg)
{
	int port = 0;
	char *s = NULL, *p = strchr(optarg, ':');

	s = strdup(optarg);

	if (p) {
		port = atoi(p + 1);
		s[p - optarg] = '\0';
	}

	if (port)
		opt_cddb_port = port;

	if (s[0] != '\0')
		opt_cddb_host = s;
}

int stdout_length(cd_trk_list *tl, int *tr_list)
{
	int i, ret = 0;

	for (i = 1; i <= tl->max; i++)
		if (tr_list[i])
			ret += tl->starts[i + 1 - tl->min] - tl->starts[i - tl->min];
	return ret;
}

#define CPARG(str) strncpy((str),optarg,BLEN); (str)[BLEN]=0

int main(int ac, char **av)
{
	static int opt_help = 0;
	int i, ret = 0, *tr_list;
	char c, all_tracks = 0, disp_TOC = 0;
	cd_trk_list tl;
	char cd_dev[BLEN + 1] = CDDEVICE;
	char filter[BLEN + 1] = "";
	char path[BLEN + 1];
	FILE *f;

#ifdef PTHREAD
	pthread_t my_thread_p;
#endif
	struct option long_options[] = {
		/* These options set a flag. */
		{"help", 0, &opt_help, SHORTHELP},
#ifdef DEBUG
		{"debug", 0, &opt_debug, 1},
#endif
		{"shorthelp", 0, &opt_help, SHORTHELP},
		{"longhelp", 0, &opt_help, LONGHELP},
		{"examples", 0, &opt_examples, 1},
		{0, 0, 0, 0}
	};

	kwords_p = kwords;

	PROGNAME = strrchr(av[0], '/');
	if (!PROGNAME++)
		PROGNAME = av[0];

	optind = 0;
	while ((c =
		getopt_long(ac, av,
			    "d:f:n:m:e:j:D:H:EhCNsivJASa",
			    long_options, NULL)) != EOF) {
		switch (c) {
		case 'a':
			all_tracks++;
			break;
		case 'h':
			opt_help = SHORTHELP;
			break;
		case 'E':
			opt_examples++;
			break;
		case 'd':
			CPARG(cd_dev);
			break;
		case 'f':
			CPARG(trackname);
			break;
		case 'i':
			disp_TOC++;
			break;
		case 'n':
			opt_blocks = atoi(optarg) /*& 0xfffc */ ;
			bad_par(&opt_blocks, 4, 2048,
				"sectors per request");
			opt_blocks0 = opt_blocks;
			break;
		case 'v':
			opt_verbose++;
			break;
		case 'm':
			opt_chmod = strtol(optarg, (char **) 0, 8);
			break;
		case 'A':
		case 'S':
			opt_save++;
			opt_cddb++;
			break;
		case 'C':
		case 'N':
			opt_name++;
			opt_cddb++;
			break;
		case 'D':
			opt_cddb_path = strdup(optarg);
			break;
		case 'H':
			set_cddb(optarg);
			break;
		case 'J':
			opt_jitter_in++;
			break;
		case 'j':
			opt_delta = atoi(optarg);
			if (opt_delta >= 128) {
				overlap = 0;
				opt_dumb++;
				opt_delta -= 128;
				if (!opt_delta) {
					opt_delta = DELTA;
					break;
				}
			}
			bad_par(&opt_delta, 4, 64, "jitter cor. delta");
			opt_jitter_in++;
			break;
		case 'e':
			CPARG(filter);
			opt_filter++;
			break;
		case 's':
			opt_spchk++;
			break;
		}
	}


	if (ac == 1)
		opt_help = SHORTHELP;

	if (opt_help) {
		show_help(opt_help);
		if (!opt_examples)
			exit(0);
	}

	if (opt_examples) {
		show_examples();
		exit(0);
	}

	if (trackname[0] == 0)
		strcpy(trackname,
		       opt_name ? "@num-@trk.wav" : "track%02d.wav");

	if (opt_chmod & ~07777) {
		opt_chmod = 0660;
		if (opt_verbose)
			dagrab_stderr( "strange chmod value, setting to 0660\n");
	}

	if (strcmp("-", trackname) == 0) {
		opt_name = 0;
		opt_stdout++;
		if (opt_verbose) {
			opt_verbose = 0;
			dagrab_stderr(
				"-f - specified -- forcing verbose mode off\n");
		}
#ifdef DEBUG
		if (opt_debug) {
			printf("[dagrab version %s]\n", DAGRAB_VERSION);
			dagrab_stderr("warning: debugging outputs to stdout\n");
		}
#endif
	}

	if (cd_getinfo(cd_dev, &tl))
		exit(1);

	if (opt_save) {
		sprintf(path, "%s/%s", cddb_getdir(""), tl.gnr);
		mkdir(path, 0777);
		/*sprintf(path, "%s/%s/%lx", cddb_getdir(), tl.gnr,
			cddb_discid(&tl));*/
		sprintf(path + strlen(path), "/%lx", cddb_discid(&tl));
		if ((f = fopen(path, "w")) == NULL) {
			char buf[2 * BLEN];
			sprintf(buf, "%s: %s", PROGNAME, path);
			perror(buf);
		} else {
			fwrite(tl.cddb, tl.cddb_size, 1, f);
			fclose(f);
		}
	}

	if (disp_TOC && !opt_stdout)
		cd_disp_TOC(&tl);
	else if (optind >= ac && !all_tracks) {
		dagrab_stderr("no track to proceed\n");
		show_help(LONGHELP);
		exit(EXIT_FAILURE);
	}

#ifdef PTHREAD	/* prepare thread */
	if (pipe(t_args.pipe[MAIN]) || pipe(t_args.pipe[THREAD])) 
		threaded = 0;
	else {
		for (i = THREAD; i >= MAIN; i--) {
			t_args.f[i][1] = fdopen(t_args.pipe[i][1], "w");
			t_args.f[i][0] = fdopen(t_args.pipe[i][0], "r");
		}

		if (pthread_create(&my_thread_p, NULL, *thread_save, NULL))
			threaded = 0;	/* for work around when not threaded */
	}
#endif
	/* compute tracks to be processed. */
	tr_list = (int *) calloc(sizeof(int), tl.max + 1);
	/* user specified track list */
	for (i = optind; i < ac; i++)
		if ((all_tracks = add_to_tr_list(av[i], tr_list, &tl))) {
			char buf[8];
			sprintf(buf, "%d-%d", tl.min, tl.max);
			add_to_tr_list(buf, tr_list, &tl);
			if (opt_verbose)
				dagrab_stderr("Dumping all tracks (%s)\n", buf);
			break;
		}
	/* loop to read cd tracks */
	for (i = 1; i <= tl.max; i++)
		if (tr_list[i])
			ret += cd_read_track(trackname, i, &tl, filter,
			stdout_length(&tl, tr_list));

	if (opt_verbose)
		dagrab_stderr("Done.\n");

#ifdef PTHREAD
	threaded = 0;
	t_args.buffer.orig = NULL;
	t_args.buffer.size = 0;
	done(MAIN);
	pthread_cancel(my_thread_p);
	pthread_join(my_thread_p, NULL);
#endif
	return ret;
}
