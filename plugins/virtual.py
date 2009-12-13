#! /usr/bin/python

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

import __init__
import re
import os

path_re = re.compile(r'%((\d+)(\.\d+)?)?([ud%])')

class PysievedPlugin(__init__.PysievedPlugin):
    def init(self, config):
        self.uid = config.getint('Virtual', 'uid', None)
        self.gid = config.getint('Virtual', 'gid', None)
        self.defaultdomain = config.get('Virtual', 'defaultdomain', 'none')
        self.path = config.get('Virtual', 'path', None)
        assert ((self.uid is not None) and
                (self.gid is not None) and
                self.path)

    def lookup(self, params):
        if self.gid >= 0:
            os.setgid(self.gid)
        if self.uid >= 0:
            os.setuid(self.uid)

        try:
            user, domain = params['username'].split('@', 1)
        except ValueError:
            user, domain = params['username'], self.defaultdomain

        def repl(m):
            l = m.group(2)
            r = m.group(3)
            c = m.group(4)
            if c == '%':
                return '%'
            elif c == 'u':
                s = user
            elif c == 'd':
                s = domain
            if l:
                l = int(l)
                if r:
                    r = int(r[1:])
                    return s[l:l+r]
                else:
                    return s[:l]
            else:
                return s
        username = path_re.sub(repl, self.path)
        return username

if __name__ == '__main__':
    c = __init__.TestConfig(uid=-1, gid=-1,
                            defaultdomain="woozle.snerk",
                            path='/shared/spool/active/%d/%0.1u/%1.1u/%u/sieve/')
    n = PysievedPlugin(None, c)
    print n.lookup({'username': 'neale@woozle.org'})
