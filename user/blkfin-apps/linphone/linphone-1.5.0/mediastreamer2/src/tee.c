/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2006  Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/

#include "mediastreamer2/msfilter.h"

static void tee_process(MSFilter *f){
	mblk_t *im;
	int i;
	while((im=ms_queue_get(f->inputs[0]))!=NULL){
		for(i=0;i<f->desc->noutputs;i++){
			if (f->outputs[i]!=NULL)
				ms_queue_put(f->outputs[i],dupmsg(im));
		}
		freemsg(im);
	}
}

#ifdef _MSC_VER

MSFilterDesc ms_tee_desc={
	MS_TEE_ID,
	"MSTee",
	"A filter that reads from output and copy to its multiple outputs.",
	MS_FILTER_OTHER,
	NULL,
	1,
	10,
    NULL,
	NULL,
	tee_process,
	NULL,
	NULL,
    NULL
};

#else

MSFilterDesc ms_tee_desc={
	.id=MS_TEE_ID,
	.name="MSTee",
	.text="A filter that reads from output and copy to its multiple outputs.",
	.category=MS_FILTER_OTHER,
	.ninputs=1,
	.noutputs=10,
	.process=tee_process
};

#endif

MS_FILTER_DESC_EXPORT(ms_tee_desc)
