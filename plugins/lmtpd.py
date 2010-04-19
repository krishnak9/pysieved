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
import FileStorage
import popen2


class PysievedPlugin(__init__.PysievedPlugin):

    def init(self, config):
        self.capabilities = ('fileinto reject envelope comparator-i;ascii-numeric relational subaddress copy')
        self.scripts_dir = config.get('lmtpd', 'scripts', '.pysieved')
        self.active_file = config.get('lmtpd', 'active', 'ssfilter')
        self.checker = config.get('lmtpd', 'checker', '/usr/bin/sieve-check')

        if not os.path.exists(self.checker):
            raise OSError('Sieve check not found')


    def create_storage(self, params):
        return FileStorage.FileStorage(self.scripts_dir,
                                       self.active_file,
                                       params['homedir'])


    def sieve_has_error(self, tmpdir, script):
        testfile = FileStorage.TempFile(tmpdir)
        testfile.write(script)
        testfile.close()

        p = popen2.Popen3(('%s %s' % (self.checker,
                                      testfile.name)),
                          True)
        p.tochild.close()
        ret_str = p.fromchild.read().strip()
        err_str = p.childerr.read().strip()
        p.fromchild.close()
        p.childerr.close()
        if p.wait():
            return err_str
        return None


    def pre_save(self, tmpdir, script):
        err_str = self.sieve_has_error(tmpdir, script)
        if err_str:
            raise ValueError(err_str)

        return script


    def post_load(self, script):
        return script


