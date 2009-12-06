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
import crypt
import pwd
import spwd
import os

class PysievedPlugin(__init__.PysievedPlugin):
    def auth(self, params):
        try:
            spwent = spwd.getspnam(params['username'])
        except KeyError:
            # This may be caused by insufficient permissions.
            # Although the result is the same, let's try and be
            # more informative about the failure case.
            # Unless the system is misconfigured, there should
            # be an entry for the current uid. If we can look
            # it up, then it is not a permissions problem.
            pwent = pwd.getpwuid(0)
            try:
                spwent = spwd.getspnam(pwent[0])
            except KeyError:
                raise NotImplementedError('insufficient permissions to authenticate against shadow database')
            return False
        sp_pwd = spwent[1]
        check = crypt.crypt(params['password'], sp_pwd)
        return check == sp_pwd

    def lookup(self, params):
        pwent = pwd.getpwnam(params['username'])
        uid = pwent[2]
        gid = pwent[3]
        os.setgid(gid)
        os.setuid(uid)
        return pwent[5]


if __name__ == '__main__':
    c = __init__.TestConfig(uid = -1, gid = -1)
    n = PysievedPlugin(None, c)

    # We use the current user for testing, otherwise the set[gu]id()
    # calls in lookup() will fail.
    pwent = pwd.getpwuid(os.getuid())
    print 'Testing with username %s' % pwent[0]
    try:
        print n.auth({'username': pwent[0], 'password': 'foobar'})
    except NotImplementedError, e:
        print str(e)
    print n.lookup({'username': pwent[0]})
