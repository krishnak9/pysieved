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
import subprocess


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

        self.log(7, 'Popen("%s %s")' % (self.checker,
                                        testfile.name))
        p = subprocess.Popen('%s %s' % (self.checker,
                                        testfile.name),
                             shell=True, stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             close_fds=True)
        (ret_str, err_str) = p.communicate()
        ret_str = ret_str.strip()
        err_str = err_str.strip()
        rc = p.returncode
        self.log(7, 'rc = %d' % rc)
        if rc:
            self.log(7, 'err_str = %s' % err_str)
            self.log(5, 'check failed')
            return err_str
        self.log(5, 'check succeeded')
        return None


    def pre_save(self, tmpdir, script):
        err_str = self.sieve_has_error(tmpdir, script)
        if err_str:
            raise ValueError(err_str)

        return script


    def post_load(self, script):
        return script


