#!/usr/bin/env python
import os, sys

global env

def configure():
    conf = Configure(env)

    check_headers = ['ldns/ldns.h', 'pcap.h', 'event.h']
    check_libs    = ['pcap', 'ldns', 'event']

    if 'LDFLAGS' in os.environ:
        env.Append(LINKFLAGS = os.environ['LDFLAGS'])
        print 'Checking Custom link flags: %s' % (os.environ['LDFLAGS'])

    if 'CFLAGS' in os.environ:
        env.Append(CFLAGS = os.environ['CFLAGS'])
        print 'Checking Custom cflags: %s' % (os.environ['CFLAGS'])

    for header in check_headers:
        if not conf.CheckCHeader(header):
            sys.exit(1)

    for lib in check_libs:
        if not conf.CheckLib(lib):
            sys.exit(1)

    env.ParseConfig('pkg-config --cflags --libs glib-2.0')

    if not conf.CheckFunc('g_ptr_array_new_with_free_func'):
        env.Append(CFLAGS='-DYOURE_PROBABLY_USING_CENTOS')

    env.Append(LIBS='event')
    env.Append(LIBS='pcap')
    env.Append(LIBS='ldns')

    env.Append(CFLAGS='-Wall -ggdb')

env = Environment(ENV=os.environ)
configure()
env.Program('dns-archiver', ['main.c', 'pktinfo.c', 'log.c', 'archiver.c'])
