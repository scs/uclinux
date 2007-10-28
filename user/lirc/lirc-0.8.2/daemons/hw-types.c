#ifdef HAVE_CONFIG_H
# include <config.h>
#endif

#include <stdio.h>
#include "hardware.h"
#include "hw-types.h"
/* Hardware types */
extern struct hardware hw_accent;
extern struct hardware hw_alsa_usb;
extern struct hardware hw_asusdh;
extern struct hardware hw_atilibusb;
extern struct hardware hw_audio;
extern struct hardware hw_audio_alsa;
extern struct hardware hw_bte;
extern struct hardware hw_bw6130;
extern struct hardware hw_creative;
extern struct hardware hw_creative_infracd;
extern struct hardware hw_default;
extern struct hardware hw_devinput;
extern struct hardware hw_dsp;
extern struct hardware hw_dvico;
extern struct hardware hw_ea65;
extern struct hardware hw_iguanaIR;
extern struct hardware hw_irman;
extern struct hardware hw_livedrive_midi;
extern struct hardware hw_livedrive_seq;
extern struct hardware hw_logitech;
extern struct hardware hw_macmini;
extern struct hardware hw_mouseremote;
extern struct hardware hw_mouseremote_ps2;
extern struct hardware hw_mp3anywhere;
extern struct hardware hw_pcmak;
extern struct hardware hw_pinsys;
extern struct hardware hw_pixelview;
extern struct hardware hw_sb0540;
extern struct hardware hw_silitek;
extern struct hardware hw_slinke;
extern struct hardware hw_tira;
extern struct hardware hw_udp;
extern struct hardware hw_uirt2;
extern struct hardware hw_uirt2_raw;
extern struct hardware hw_usb_uirt_raw;
extern struct hardware hw_usbx;


#ifndef HW_DEFAULT
# define HW_DEFAULT hw_default
# warning HW_DEFAULT is not defined
#endif

struct hardware hw_null=
{
	"/dev/null",        /* default device */
	-1,                 /* fd */
	0,                  /* features */
	0,                  /* send_mode */
	0,                  /* rec_mode */
	0,                  /* code_length */
	NULL,               /* init_func */
	NULL,               /* config_func */
	NULL,               /* deinit_func */
	NULL,               /* send_func */
	NULL,               /* rec_func */
	NULL,               /* decode_func */
	NULL,               /* ioctl_func */
	NULL,		    /* readdata */
	"null",		    /* name */
};

struct hardware *hw_list[] =
{
#ifdef LIRC_DRIVER_ANY
	&hw_accent,
#ifdef HAVE_ALSA_SB_RC
	&hw_alsa_usb,
#endif
	&hw_asusdh,
#ifdef HAVE_LIBUSB
	&hw_atilibusb,
#endif
#ifdef HAVE_LIBPORTAUDIO
	&hw_audio,
#endif
#ifdef HAVE_LIBALSA
	&hw_audio_alsa,
#endif
	&hw_bte,
	&hw_bw6130,
	&hw_creative,
#ifdef HAVE_SCSI
	&hw_creative_infracd,
#endif
	&hw_default,
#ifdef HAVE_LINUX_DEVINPUT
	&hw_devinput,
#endif
#ifdef HAVE_SOUNDCARD
	&hw_dsp,
#endif
	&hw_dvico,
	&hw_ea65,
#ifdef HAVE_IGUANAIR
	&hw_iguanaIR,
#endif
#ifdef HAVE_LIBIRMAN
	&hw_irman,
#endif
	&hw_livedrive_midi,
	&hw_livedrive_seq,
	&hw_logitech,
	&hw_mp3anywhere,
	&hw_mouseremote,
	&hw_mouseremote_ps2,
	&hw_null,
	&hw_pcmak,
	&hw_pinsys,
	&hw_pixelview,
	&hw_sb0540,
	&hw_silitek,
	/*	&hw_slinke,*/
	&hw_tira,
	&hw_udp,
	&hw_uirt2,
	&hw_uirt2_raw,
	&hw_usb_uirt_raw,
	&hw_usbx,
#else
	&HW_DEFAULT,
#endif
	NULL
};

struct hardware hw;

// which one is HW_DEFAULT could be selected with autoconf in a similar
// way as it is now done upstream

int hw_choose_driver (char *name)
{
	int i;
	
	if(name==NULL){
		hw = HW_DEFAULT;
		return 0;
	}
	for (i=0; hw_list[i]; i++)
		if (!strcasecmp (hw_list[i]->name, name))
			break;
	if (!hw_list[i])
		return -1;
	hw = *hw_list[i];

	return 0;
} 

void hw_print_drivers (FILE *file)
{
	int i;
	fprintf(file, "Supported drivers:\n");
	for (i = 0; hw_list[i]; i++)
		fprintf (file, "\t%s\n", hw_list[i]->name);
}
