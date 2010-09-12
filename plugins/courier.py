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
import warnings
import os
import socket


class PysievedPlugin(__init__.PysievedPlugin):

    def __fetchAuth(self, username, password):
        if len(self.mux)==0:
            return ''

        self.log(7, 'Opening socket %s' % self.mux)
        try:
            authSocket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            authSocket.connect(self.mux)
        except Error:
            return ''

        if password is None:
            authBuffer = 'PRE . %s %s\n' % (self.service, username)
        else:
            authBuffer = '%s\nlogin\n%s\n%s\n' % (self.service, username, password)
            authBuffer = 'AUTH %d\n%s' % (len(authBuffer), authBuffer)

        self.log(7, '> %r' % authBuffer)
        authSocket.sendall(authBuffer)

        authBuffer = authSocket.recv(2048)
        self.log(7, '< %r' % authBuffer)

        self.log(7, 'Closing socket %s' % self.mux)
        authSocket.close()

        return authBuffer


    def init(self, config):
        self.mux = config.get('Courier', 'mux', '')
        self.uid = config.getint('Courier', 'uid', -1)
        self.gid = config.getint('Courier', 'gid', -1)
        self.service = config.get('Courier', 'service', 'managesieve')

        # Drop privileges here if all users share the same uid/gid
        if self.gid >= 0:
            os.setgid(self.gid)
        if self.uid >= 0:
            os.setuid(self.uid)


    def auth(self, params):
        authBuffer = self.__fetchAuth(params['username'], params['password'])
        if len(authBuffer) == 0:
            return False
        for authLine in authBuffer.split('\n'):
            if authLine.find('USERNAME') == 0:
                return True
            if authLine.find('UID') == 0:
                return True
        return False


    def lookup(self, params):
        authBuffer = self.__fetchAuth(params['username'], None)
        if len(authBuffer) == 0:
            return False

        newUid = -1
        newGid = -1
        maildir = None
        for authLine in authBuffer.split('\n'):
            if authLine.find('MAILDIR') == 0:
                maildir = authLine.split('=')[1]
            elif authLine.find('GID') == 0:
                newUid = int(authLine.split('=')[1])
            elif authLine.find('UID') == 0:
                newGid = int(authLine.split('=')[1])

        # TODO - check privileges, and drop them if neccecery
        if newGid >= 0 and self.gid == -1:
            os.setgid(newGid)
        if newUid >= 0 and self.uid == -1:
            os.setuid(newUid)

        return maildir


