#!/usr/bin/python -tt

import crypt
import os
import re
import sys

import ldap
import ldap.filter

import __init__


expand_re = re.compile('%[udlm]')


scope_map = {
    'base': ldap.SCOPE_BASE,
    'sub': ldap.SCOPE_SUBTREE,
    'one': ldap.SCOPE_ONELEVEL,
}


class PysievedPlugin(__init__.PysievedPlugin):
    def init(self, config):
        self.ldap_url = config.get('LDAP', 'ldap_url', None)
        self.bind_dn = config.get('LDAP', 'bind_dn', None)
        self.bind_pw = config.get('LDAP', 'bind_pw', None)
        self.auth_bind = config.getboolean('LDAP', 'auth_bind', True)
        self.base = config.get('LDAP', 'base', '')
        self.scope = scope_map[config.get('LDAP', 'scope', 'sub')]
        self.filter = config.get('LDAP', 'filter', 'uid=%u')
        self.default_domain = config.get('LDAP', 'default_domain', None)
        self.default_uid = config.getint('LDAP', 'default_uid', -1)
        self.default_gid = config.getint('LDAP', 'default_gid', -1)
        self.pw_attr = config.get('LDAP', 'pw_attr', 'userPassword')
        self.uid_attr = config.get('LDAP', 'uid_attr', 'uidNumber')
        self.gid_attr = config.get('LDAP', 'gid_attr', 'gidNumber')
        self.home_attr = config.get('LDAP', 'home_attr', 'homeDirectory')
        assert ((self.ldap_url is not None) and
                (self.bind_dn is not None) and
                (self.bind_pw is not None))


    def expand_filter(self, filter, params):
        # Here are the possible substitutions.
        login = params['username']
        try:
            user, domain = login.split('@', 1)
        except ValueError:
            user, domain = params['username'], self.default_domain
        if domain is not None:
            email = '@'.join([user, domain])
        else:
            email = None

        # We need to provide as many arguments to ldap.filter.filter_format()
        # as there are substitution patterns in the filter.
        values = []
        for match in expand_re.finditer(filter):
            sub = match.group()
            if sub == '%u':
                values.append(user)
            elif sub == '%d':
                if not domain:
                    raise RuntimeError('undefined domain in filter expansion')
                values.append(domain)
            elif sub == '%l':
                values.append(login)
            elif sub == '%m':
                if not email:
                    raise RuntimeError('incomplete e-mail address in filter expansion')
                values.append(email)
            next = match.end()

        # ldap.filter.filter_format() expands '%s'.
        format = re.sub(expand_re, '%s', filter)

        return ldap.filter.filter_format(format, values)


    def auth(self, params):
        # Connect to server.
        self.log(7, 'Connecting to %s' % self.ldap_url)
        ld = ldap.initialize(self.ldap_url)
        self.log(8, 'Binding as %s' % self.bind_dn)
        ld.simple_bind_s(self.bind_dn, self.bind_pw)

        # Look for account.
        filter = self.expand_filter(self.filter, params)
        self.log(8, 'Searching for %s (base: %s)' % (filter, self.base))
        results = ld.search_s(self.base, self.scope, filter, [self.pw_attr])

        if not results:
            self.log(8, 'No match for %s' % filter)
            self.log(7, 'Disconnecting from %s' % self.ldap_url)
            ld.unbind_s()
            return False

        dn = results[0][0]
        self.log(8, 'Found entry %s' % dn)

        if self.auth_bind:
            # Try the bind method.
            try:
                self.log(8, 'Attempting bind as %s' % dn)
                ld.simple_bind_s(dn, params['password'])
                self.log(8, 'Bind succeeded for %s' % dn)
                result = True
            except ldap.INVALID_CREDENTIALS:
                self.log(8, 'Bind failed for %s' % dn)
                result = False
        else:
            # Grab the password so we can check it.
            if self.pw_attr not in results[0][1]:
                raise RuntimeError('no password attribute was returned')
            pw = results[0][1][self.pw_attr][0]

            # Is it a crypted password ?
            if pw.lower().startswith('{crypt}'):
                self.log(8, 'This is a crypted password')
                pw = pw[7:]
                check = crypt.crypt(params['password'], pw)
                result = check == pw
            else:
                # Compare clear-text passwords.
                result = params['password'] == pw

        self.log(8, 'Good password ? %s' % result)

        # All done.
        self.log(7, 'Disconnecting from %s' % self.ldap_url)
        ld.unbind_s()

        return result


    def lookup(self, params):
        # Connect to server.
        self.log(7, 'Connecting to %s' % self.ldap_url)
        ld = ldap.initialize(self.ldap_url)
        self.log(7, 'Binding as %s' % self.bind_dn)
        ld.simple_bind_s(self.bind_dn, self.bind_pw)

        # Look for account.
        filter = self.expand_filter(self.filter, params)
        self.log(8, 'Searching for %s (base = %s)' % (filter, self.base))
        results = ld.search_s(self.base, self.scope, filter,
                              [self.home_attr, self.uid_attr, self.gid_attr])

        if not results:
            self.log(8, 'No match for %s' % filter)
            self.log(7, 'Disconnecting from %s' % self.ldap_url)
            ld.unbind_s()
            return None

        dn = results[0][0]
        self.log(8, 'Found entry %s' % dn)
        home = results[0][1].get(self.home_attr, [None])[0]
        self.log(8, 'Home is %s' % home)

        # Change uid/gid if found.
        uid = results[0][1].get(self.uid_attr, [None])[0]
        gid = results[0][1].get(self.gid_attr, [None])[0]
        if gid is not None and (int(gid) > 0):
            os.setgid(int(gid))
        elif self.default_gid > 0:
            os.setgid(self.default_gid)
        if uid is not None and (int(uid) > 0):
            os.setuid(int(uid))
        elif self.default_uid > 0:
            os.setuid(self.default_uid)

        # All done.
        self.log(7, 'Disconnecting from %s' % self.ldap_url)
        ld.unbind_s()

        return home



if __name__ == '__main__':
    c = __init__.TestConfig(ldap_url = 'ldap://127.0.0.1',
                            bind_dn = 'cn=root',
                            bind_pw = 'foobar',
                            auth_bind = True,
                            default_domain = 'epix.net',
                            default_uid = -1, default_gid = -1)
    n = PysievedPlugin(None, c)
    print n.expand_filter('u = %u, d = %d, l = %l, m = %m',
                          {'username': 'levan'})
    print n.auth({'username': 'levan',
                  'password': 'foobar'})
    print n.lookup({'username': 'levan'})
