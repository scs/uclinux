/*
 * X-Mame sound code
 */

#include "xmame.h"
#include "sysdep/sysdep_dsp.h"
#include "sysdep/sysdep_mixer.h"
#include "sysdep/sysdep_sound_stream.h"
#include "driver.h"

/* #define SOUND_DEBUG */

static float sound_bufsize = 3.0;
static int sound_attenuation = -3;
static char *sound_dsp_device = NULL;
static char *sound_mixer_device = NULL;
static struct sysdep_dsp_struct *sysdep_sound_dsp = NULL;
static struct sysdep_mixer_struct *sysdep_sound_mixer = NULL;
static int sound_samples_per_frame = 0;
static int type = -1;

struct rc_option sound_opts[] = {
	/* name, shortname, type, dest, deflt, min, max, func, help */
	{ "Sound Related", NULL, rc_seperator, NULL, NULL, 0, 0, NULL, NULL },
	{ "samples", "sam", rc_bool, &options.use_samples, "1", 0, 0, NULL, "Use/don't use samples (if available)" },
	{ "samplefreq", "sf", rc_int, &(options.samplerate), "44100", 8000, 48000, NULL, "Set the playback sample-frequency/rate" },
	{ "bufsize",  "bs", rc_float, &sound_bufsize, "3.0", 1.0, 30.0, NULL, "Number of frames of sound to buffer" },
	{ "volume", "v", rc_int, &sound_attenuation, "-3", -32, 0, NULL, "Set volume to <int> db, (-32 (soft) - 0(loud) )" },
	{ "audiodevice", "ad", rc_string, &sound_dsp_device, NULL, 0, 0, NULL, "Use an alternative audiodevice" },
	{ "mixerdevice", "md", rc_string, &sound_mixer_device, NULL, 0, 0, NULL, "Use an alternative mixerdevice" },
	{ NULL, NULL, rc_end, NULL, NULL, 0, 0, NULL, NULL }
};

void sound_update_refresh_rate(float newrate)
{
	sound_samples_per_frame = Machine->sample_rate / Machine->refresh_rate;
}

/* attenuation in dB */
void osd_set_mastervolume(int attenuation)
{
	float f = attenuation;

	if(!sysdep_sound_mixer)
		return;

	f += 32.0;
	f *= 100.0;
	f /= 32.0;
	f += 0.50; /* for rounding */
#ifdef SOUND_DEBUG
	fprintf(stderr, "sound.c: setting volume to %d (%d)\n",
			attenuation, (int)f);
#endif

	sysdep_mixer_set(sysdep_sound_mixer, SYSDEP_MIXER_PCM1, f, f);
}

int osd_get_mastervolume(void)
{
	int left, right;
	float f;

	if(!sysdep_sound_mixer)
		return -32;

	if(sysdep_mixer_get(sysdep_sound_mixer, SYSDEP_MIXER_PCM1, &left, &right))
		return -32;

	f = left;
	f *= 32.0;
	f /= 100.0;
	f -= 32.5; /* 32 + 0.5 for rounding */
#ifdef SOUND_DEBUG
	fprintf(stderr, "sound.c: got volume %d (%d)\n", (int)f, left);
#endif
	return f;
}

void osd_sound_enable(int enable_it)
{
	if (enable_it)
	{
		/* in case we get called twice with enable_it true
		   OR we get called when osd_start_audio stream
		   has never been called */
		if (sysdep_sound_dsp || (type==-1))
			return;
		
		if(!(sysdep_sound_dsp = sysdep_dsp_create(NULL,
						sound_dsp_device,
						&(Machine->sample_rate),
						&type,
						sound_bufsize * (1 / Machine->refresh_rate),
						SYSDEP_DSP_EMULATE_TYPE | SYSDEP_DSP_O_NONBLOCK)))
		{
			Machine->sample_rate = 8000;
		}

		/* calculate samples_per_frame */
		sound_samples_per_frame = Machine->sample_rate /
			Machine->refresh_rate;

		if(sysdep_sound_dsp && !(sysdep_sound_stream = sysdep_sound_stream_create(sysdep_sound_dsp,
						type, sound_samples_per_frame, 3)))
		{
			sysdep_dsp_destroy(sysdep_sound_dsp);
			sysdep_sound_dsp = NULL;
		}

	}
	else
	{
		if (sysdep_sound_dsp)
		{
			sysdep_dsp_destroy(sysdep_sound_dsp);
			sysdep_sound_dsp = NULL;
		}
		if (sysdep_sound_stream)
		{
			sysdep_sound_stream_destroy(sysdep_sound_stream);
			sysdep_sound_stream = NULL;
		}
	}
}

int osd_start_audio_stream(int stereo)
{
	type = SYSDEP_DSP_16BIT | (stereo? SYSDEP_DSP_STEREO:SYSDEP_DSP_MONO);

	sysdep_sound_dsp    = NULL;
	sysdep_sound_stream = NULL;
	sysdep_sound_mixer  = NULL;

	osd_sound_enable(1);
	
	if (sysdep_sound_dsp)
	{
		/* create a mixer instance */
		sysdep_sound_mixer = sysdep_mixer_create(NULL, sound_mixer_device,
			SYSDEP_MIXER_RESTORE_SETTINS_ON_EXIT);

		/* check if the user specified a volume, and ifso set it */
		if(sysdep_sound_mixer && rc_get_priority2(sound_opts, "volume"))
			osd_set_mastervolume(sound_attenuation);
	}

	return sound_samples_per_frame;
}

int osd_update_audio_stream(INT16 *buffer)
{
	if (sysdep_sound_stream)
		sysdep_sound_stream_write(sysdep_sound_stream, (unsigned char *)buffer,
				sound_samples_per_frame);

	return sound_samples_per_frame;
}

void osd_stop_audio_stream(void)
{
	if(sysdep_sound_mixer)
	{
		sysdep_mixer_destroy(sysdep_sound_mixer);
		sysdep_sound_mixer = NULL;
	}
	
	osd_sound_enable(0);
}
