;*
;* $Id$
;* ---------------------------------------------------------------------------
;* Each SFX  archive  contains a  self-identifier  in  its  code  segment. The
;* purpose of this module is to hold this sequence of bytes.
;*

INCLUDE         ASM_INCL.INC

.CODE _TEXT

;*
;* A unique pattern for identifying SFX
;*

id              db      "zyxwbaaRJsfXaRJsfX"

        	end
