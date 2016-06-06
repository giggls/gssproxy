
t_acquire_SOURCES = \
    t_utils.c \
    t_acquire.c

t_acquire_LDADD = \
    $(GSSAPI_LIBS)

t_accept_SOURCES = \
    t_utils.c \
    t_accept.c

t_accept_LDADD = \
    $(GSSAPI_LIBS)

t_impersonate_SOURCES = \
    t_utils.c \
    t_impersonate.c

t_impersonate_LDADD = \
    $(GSSAPI_LIBS)

t_init_SOURCES = \
    t_utils.c \
    t_init.c

t_init_LDADD = \
    $(GSSAPI_LIBS)

t_delegate_SOURCES = \
    t_utils.c \
    t_delegate.c

t_delegate_LDADD = \
    $(GSSAPI_LIBS)

check_PROGRAMS = \
    t_acquire \
    t_impersonate \
    t_accept \
    t_init \
    t_delegate

noinst_PROGRAMS = $(check_PROGRAMS)

noinst_HEADERS = \
    t_utils.h

all: $(check_PROGRAMS)
