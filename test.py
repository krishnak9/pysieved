#! /usr/bin/env python

## pysieved - Python managesieve server
## Copyright (C) 2007 Neale Pickett

## This program is free software; you can redistribute it and/or modify
## it under the terms of the GNU General Public License as published by
## the Free Software Foundation; either version 2 of the License, or (at
## your option) any later version.

## This program is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.

## You should have received a copy of the GNU General Public License
## along with this program; if not, write to the Free Software
## Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
## USA

import getpass
import optparse
import os
import pwd
import socket
import sys
import unittest

from config import Config
from plugins import TestConfig


DEFAULT = {
    'config': './test.ini',
    # This will be replaced currently logged-in user.
    'user': 'foor',
    'password': '',
    # This will be replaced by the current host's domain.
    'domain': 'example.org',
    'uid': -1,
    'gid': -1,
    'verbosity': 0,
}


class PluginsTest(unittest.TestCase):
    def setUp(self):
        global CONF
        global config
        self.conf = CONF
        self.config = config

        if self.conf['verbosity'] > 0:
            print


    def tearDown(self):
        sys.stdout.flush()


    def testDovecotAuth(self):
        try:
            from plugins import dovecot
        except ImportError:
            print 'skipping (deps), ',
            return

        if self.config.getboolean('Dovecot', 'skip', False):
            print 'skipping (conf), ',
            return

        mux = self.config.get('Dovecot', 'mux', '')

        if not mux:
            print 'skipping (conf), ',
            return

        c = TestConfig(mux = mux, master = '',
                       uid = -1, gid = -1)
        p = dovecot.PysievedPlugin(printlog, c)

        self.generic_sasl(p, self.conf['user'], self.conf['password'])


    def testDovecotLookup(self):
        try:
            from plugins import dovecot
        except ImportError:
            print 'skipping (deps), ',
            return

        if self.config.getboolean('Dovecot', 'skip', False):
            print 'skipping (conf), ',
            return

        master = self.config.get('Dovecot', 'master', '')

        if not master:
            print 'skipping (conf), ',
            return

        c = TestConfig(mux = '', master = master,
                       uid = -1, gid = -1)
        p = dovecot.PysievedPlugin(printlog, c)

        self.generic_lookup(p, self.conf['user'])


    def testHtpasswdAuth(self):
        try:
            from plugins import htpasswd
        except ImportError:
            print 'skipping (deps), ',
            return

        if self.config.getboolean('htpasswd', 'skip', False):
            print 'skipping (conf), ',
            return

        passfile = self.config.get('htpasswd', 'passwdfile', '')

        if not passfile:
            print 'skipping (conf), ',
            return

        c = TestConfig(passwdfile = passfile)
        p = htpasswd.PysievedPlugin(printlog, c)

        if '@' in self.conf['user']:
            user = self.conf['user'].split('@')[0]
        else:
            user = self.conf['user']

        self.generic_auth(p, user, self.conf['password'])
        self.generic_sasl(p, user, self.conf['password'])


    def testMysqlAuth(self):
        try:
            from plugins import mysql
        except ImportError:
            print 'skipping (deps), ',
            return

        if self.config.getboolean('MySQL', 'skip', False):
            print 'skipping (conf), ',
            return

        dbhost = self.config.get('MySQL', 'dbhost', '')
        dbname = self.config.get('MySQL', 'dbname', '')
        dbuser = self.config.get('MySQL', 'dbuser', '')
        dbpass = self.config.get('MySQL', 'dbpass', '')
        auth_query = self.config.get('MySQL', 'auth_query', '')

        if not (dbhost and dbname and dbuser and dbpass and auth_query):
            print 'skipping (conf), ',
            return

        c = TestConfig(dbhost = dbhost, dbname = dbname,
                       dbuser = dbuser, dbpass = dbpass,
                       auth_query = auth_query, user_query = '')
        p = mysql.PysievedPlugin(printlog, c)

        self.generic_auth(p, self.conf['user'], self.conf['password'])
        self.generic_sasl(p, self.conf['user'], self.conf['password'])


    def testMysqlLookup(self):
        try:
            from plugins import mysql
        except ImportError:
            print 'skipping (deps), ',
            return

        if self.config.getboolean('MySQL', 'skip', False):
            print 'skipping (conf), ',
            return

        dbhost = self.config.get('MySQL', 'dbhost', '')
        dbname = self.config.get('MySQL', 'dbname', '')
        dbuser = self.config.get('MySQL', 'dbuser', '')
        dbpass = self.config.get('MySQL', 'dbpass', '')
        user_query = self.config.get('MySQL', 'user_query', '')

        if not (dbhost and dbname and dbuser and dbpass and user_query):
            print 'skipping (conf), ',
            return

        c = TestConfig(dbhost = dbhost, dbname = dbname,
                       dbuser = dbuser, dbpass = dbpass,
                       auth_query = '', user_query = user_query)
        p = mysql.PysievedPlugin(printlog, c)

        self.generic_lookup(p, self.conf['user'])


    def testPamAuth(self):
        try:
            from plugins import pam
        except ImportError:
            print 'skipping (deps), ',
            return

        if self.config.getboolean('PAM', 'skip', False):
            print 'skipping (conf), ',
            return

        service = config.get('PAM', 'service', 'pysieved')

        c = TestConfig(service = service)
        p = pam.PysievedPlugin(printlog, c)

        if '@' in self.conf['user']:
            user = self.conf['user'].split('@')[0]
        else:
            user = self.conf['user']

        self.generic_auth(p, user, self.conf['password'])
        self.generic_sasl(p, user, self.conf['password'])


    def testPasswdLookup(self):
        try:
            from plugins import passwd
        except ImportError:
            print 'skipping (deps), ',
            return

        if self.config.getboolean('passwd', 'skip', False):
            print 'skipping (conf), ',
            return

        c = TestConfig()
        p = passwd.PysievedPlugin(printlog, c)

        if '@' in self.conf['user']:
            user = self.conf['user'].split('@')[0]
        else:
            user = self.conf['user']

        self.generic_lookup(p, user)


    def testSaslAuth(self):
        try:
            from plugins import sasl
        except ImportError:
            print 'skipping (deps), ',
            return

        if self.config.getboolean('SASL', 'skip', False):
            print 'skipping (conf), ',
            return

        mux = config.get('SASL', 'mux', '')
        service = config.get('SASL', 'service', 'pysieved')

        if not mux:
            print 'skipping (conf), ',
            return

        c = TestConfig(mux = mux, service = service)
        p = sasl.PysievedPlugin(printlog, c)

        self.generic_auth(p, self.conf['user'], self.conf['password'])
        self.generic_sasl(p, self.conf['user'], self.conf['password'])


    def testVirtualLookup(self):
        try:
            from plugins import virtual
        except ImportError:
            print 'skipping (deps), ',
            return

        if self.config.getboolean('Virtual', 'skip', False):
            print 'skipping (conf), ',
            return

        c = TestConfig(uid = -1, gid = -1,
                       defaultdomain = self.conf['domain'],
                       path = '/shared/spool/active/%d/%0.1u/%1.1u/%u/sieve/')
        p = virtual.PysievedPlugin(printlog, c)

        try:
            user, domain = self.conf['user'].split('@', 1)
        except ValueError:
            user, domain = self.conf['user'], self.conf['domain']

        home = p.lookup({'username': user})
        printlog(2, 'lookup(%s) = %s' % (user, home))
        self.assertEqual('/shared/spool/active/%s/%s/%s/%s/sieve/' %
                         (self.conf['domain'], user[0], user[1], user),
                         home)

        home = p.lookup({'username': '@'.join([user, domain])})
        printlog(2, 'lookup(%s) = %s' % ('@'.join([user, domain]), home))
        self.assertEqual('/shared/spool/active/%s/%s/%s/%s/sieve/' %
                         (domain, user[0], user[1], user),
                         home)


    def generic_auth(self, plugin, login, password):
        auth = plugin.auth({'username': login, 'password': password})
        printlog(2, 'auth(%s) = %r' % (login, auth))
        self.assert_(auth)


    def generic_sasl(self, plugin, login, password):
        mechs = plugin.mechanisms()
        printlog(2, 'mechanisms() = %r' % mechs)
        self.assert_('PLAIN' in mechs)

        auth = plugin.do_sasl_first('PLAIN',
                                    b64_encode('\0%s\0%s' %
                                               (login, password)))
        printlog(2, 'do_sasl_first(%s) = %r' % (login, auth))
        self.assert_('result' in auth)
        self.assert_(auth['result'] in ('OK', 'NO', 'BYE', 'CONT'))
        self.assertEquals('OK', auth['result'])
        self.assert_('username' in auth)


    def generic_lookup(self, plugin, user):
        home = plugin.lookup({'username': user})
        printlog(2, 'lookup(%s) = %r' % (user, home))
        self.assert_(home is not None)


def printlog(l, s):
    global CONF
    if l <= CONF['verbosity']:
        print '=' * l, s


def b64_encode(s):
    return s.encode('base64').replace('\n', '')


def pick(name, options, config, defaults = {}, type = 'string'):
    # Command-line options take priority.
    try:
        value = getattr(options, name)
    except AttributeError:
        value = None
    except:
        raise

    # Try values from the configuration file next.
    if not value:
        if type == 'int':
            value = config.getint('Test', name, defaults.get(name, -1))
        else:
            value = config.get('Test', name, defaults.get(name, None))

    return value


def main(defaults):
    global CONF
    global config

    # Parse command-line options.
    parser = optparse.OptionParser()
    parser.add_option('-c', '--config',
                      help='Configuration file (default: %s)' %
                           defaults.get('config', None),
                      action='store', dest='config',
                      default=defaults.get('config', None))
    parser.add_option('-d', '--domain',
                      help='Default domain',
                      action='store', dest='domain', default=None)
    parser.add_option('-u', '--user',
                      help='Test username',
                      action='store', dest='user', default=None)
    parser.add_option('-p', '--password',
                      help='Test password',
                      action='store', dest='password', default=None)
    parser.add_option('-U', '--uid',
                      help='Default uid', \
                      action='store', type='int', dest='uid', default=None)
    parser.add_option('-G', '--gid',
                      help='Default gid',
                      action='store', type='int', dest='gid', default=None)
    parser.add_option('-v', '--verbosity',
                      help='Verbosity level',
                      action='store', type='int', dest='verbosity', default=0)

    (options, args) = parser.parse_args()

    # Read config file.
    config = Config(options.config)

    # Build test configuration.
    CONF = {}
    CONF['user'] = pick('user', options, config, defaults)
    CONF['password'] = pick('password', options, config, defaults)
    CONF['domain'] = pick('domain', options, config, defaults)
    CONF['uid'] = pick('uid', options, config, defaults, 'int')
    CONF['gid'] = pick('gid', options, config, defaults, 'int')
    CONF['verbosity'] = pick('verbosity', options, config, defaults, 'int')

    print 'Testing with :'
    print '\tuser     =\t%s' % CONF['user']
    print '\tdomain   =\t%s' % CONF['domain']
    print '\tuid      =\t%d' % CONF['uid']
    print '\tgid      =\t%d' % CONF['gid']
    print

    if not CONF['password']:
        CONF['password'] = getpass.getpass('%s\'s password: ' % CONF['user'])
        print

    # Run test suite.
    suite = unittest.TestLoader().loadTestsFromTestCase(PluginsTest)
    unittest.TextTestRunner(verbosity=2).run(suite)


if __name__ == '__main__':
    # User currently logged-in user as default.
    try:
        pw = pwd.getpwuid(os.getuid())
        DEFAULT['user'] = pw[0]
    except:
        pass

    # Try and derive the domain from the current host's FQDN.
    try:
        fqdn = socket.getfqdn()
        if '.' in fqdn:
            DEFAULT['domain'] = '.'.join(fqdn.split('.')[-2:])
    except:
        pass

    main(DEFAULT)
