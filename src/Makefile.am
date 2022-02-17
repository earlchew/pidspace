# Copyright (c) 2022, Earl Chew
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the names of the authors of source code nor the names
#       of the contributors to the source code may be used to endorse or
#       promote products derived from this software without specific
#       prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL EARL CHEW BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

VERSION = 1.0.0
LDADD   =

AM_CPPFLAGS   = -I.
AM_CFLAGS     = $(TEST_CFLAGS)
AM_CXXFLAGS   = $(TEST_CXXFLAGS)
AM_LDFLAGS    =

OPT_FLAGS          = -O2
COMMON_FLAGS       = $(OPT_FLAGS)
COMMON_FLAGS      += -D_GNU_SOURCE -Wall -Werror
COMMON_FLAGS      += -Wno-parentheses -Wshadow
COMMON_CFLAGS      = $(COMMON_FLAGS) -std=gnu99
COMMON_CFLAGS     += -fdata-sections -ffunction-sections
COMMON_CFLAGS     += -Wmissing-prototypes -Wmissing-declarations
COMMON_CXXFLAGS    = $(COMMON_FLAGS) -std=gnu++0x
COMMON_CXXFLAGS   += -Wno-variadic-macros -Wno-long-long
COMMON_LINKFLAGS   = -Wl,--gc-sections

pidspacedir        = $(bindir)
pidspace_PROGRAMS  = pidspace
check_SCRIPTS      =
check_PROGRAMS     =
noinst_PROGRAMS    =
noinst_SCRIPTS     = $(check_SCRIPTS)
noinst_LTLIBRARIES =
lib_LTLIBRARIES    =

pidspace_CFLAGS    = $(COMMON_CFLAGS)
pidspace_LDFLAGS   = $(COMMON_LINKFLAGS)
pidspace_LDADD     = -lcap
pidspace_SOURCES   = pidspace.c

man1dir            = $(mandir)/cat1
man1_MANS          = pidspace.1
EXTRA_DIST         = $(man1_MANS)

%.1:	%.man
	rm -f $@
	$(NROFF) -man $< > $@~
	mv $@~ $@

install-data-hook:
	sudo chown root '$(DESTDIR)$(bindir)/pidspace'
	sudo chmod u+s '$(DESTDIR)$(bindir)/pidspace'
	./test.sh '$(DESTDIR)$(bindir)/pidspace'

programs:	all
	$(MAKE) $(AM_MAKEFLAGS) $(check_PROGRAMS) $(check_SCRIPTS)
