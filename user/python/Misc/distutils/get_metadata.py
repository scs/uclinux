#!/usr/bin/env python

"""get_metadata

Pry open a setup script and pick out the juicy bits, ie. the
distribution meta-data.
"""

# created 2000/08/30, GPW

__revision__ = "$Id$"

import sys
from distutils.core import run_setup

USAGE = "usage: %(script)s setup_script\n"


def main (script, args):
    if len(args) != 1:
        raise SystemExit, (USAGE % vars()) + "\nWrong number of arguments"

    setup_script = args[0]
    dist = run_setup(setup_script, script_args=[], stop_after="init")
    print """\
%s is the setup script for %s; description:
%s

contact:  %s <%s>
info url: %s
licence:  %s
""" % (setup_script, dist.get_fullname(), dist.get_description(),
       dist.get_contact(), dist.get_contact_email(),
       dist.get_url(), dist.get_licence())

if __name__ == "__main__":
    main(sys.argv[0], sys.argv[1:])
