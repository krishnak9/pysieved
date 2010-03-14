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

import MySQLdb
import re

import __init__


expand_re = re.compile('\%\((username|password|name|script)\)s|"\%\((username|password|name|script)\)s"')

def expand_query(query, params):
    values = []
    for match in expand_re.finditer(query):
        sub = match.group().replace('"', '')
        if sub == '%(username)s':
            values.append(params['username'])
        elif sub == '%(password)s':
            values.append(params['password'])
        elif sub == '%(script)s':
            values.append(params['script'])
        elif sub == '%(content)s':
            values.append(params['content'])

    query = re.sub(expand_re, '%s', query)

    return (query, values)


class MysqlStorage(__init__.ScriptStorage):
    def init(self, conn, params, config):
        self.conn = conn
        self.params = params
        self.list_query = config.get('MySQL', 'list_query')
        self.get_query = config.get('MySQL', 'get_query')
        self.update_query = config.get('MySQL', 'update_query')
        self.inset_query = config.get('MySQL', 'inset_query')
        self.delete_query = config.get('MySQL', 'delete_query')
        self.active_query = config.get('MySQL', 'active_query')
        self.set_active_query = config.get('MySQL', 'set_active_query')
        self.clear_active_query = config.get('MySQL', 'clear_active_query')

    def __iter__(self):
        query, values = expand_query(self.list_query,
                                     dict(params))
        cursor = self.conn.cursor()
        cursor.execute(query, values)
        results = cursor.fetchall()
        for row in results:
            if row:
                yield row[0]
            else:
                break

    def has_key(self, k):
        query, values = expand_query(self.get_query,
                                     dict(params,
                                          name = k))
        cursor = self.conn.cursor()
        cursor.execute(query, values)
        if cursor.fetchone():
            return True
        return False

    def __getitem__(self, k):
        if k != None and not self.has_key(k):
            raise KeyError('Unknown script')
        query, values = expand_query(self.get_query,
                                     dict(params,
                                          name = k))
        cursor = self.conn.cursor()
        cursor.execute(query, values)
        row = cursor.fetchone()
        return row[0]

    def __setitem__(self, k, v):
        if self.has_key(k):
            query, values = expand_query(self.update_query,
                                         dict(params,
                                              name = k,
                                              script = v))
        else:
            query, values = expand_query(self.insert_query,
                                         dict(params,
                                              name = k,
                                              script = v))
        cursor = self.conn.cursor()
        cursor.execute(query, values)

    def __delitem__(self, k):
        if self.is_active(k):
            raise ValueError('Script is active')
        query, values = expand_query(self.delete_query,
                                     dict(params,
                                          name = k))
        cursor = self.conn.cursor()
        cursor.execute(query, values)

    def get_active(self):
        query, values = expand_query(self.active_query,
                                     dict(params))
        cursor = self.conn.cursor()
        cursor.execute(query, values)
        row = cursor.fetchone()
        if row:
            return row[0]
        return None

    def is_active(self, k):
        if k != None and not self.has_key(k):
             raise KeyError('Unknown script')
        return self.get_active() == k

    def set_active(self, k):
        if k:
            if not self.has_key(k):
                raise KeyError('Unknown script')
        query, values = expand_query(self.clear_active_query,
                                     dict(params,
                                          name = active))
        cursor = self.conn.cursor()
        cursor.execute(query, values)
        if k:
            query, values = expand_query(self.set_active_query,
                                         dict(params,
                                              name = k))
            cursor = self.conn.cursor()
            cursor.execute(query, values)


class PysievedPlugin(__init__.PysievedPlugin):
    def init(self, config):
        dbhost = config.get('MySQL', 'dbhost')
        dbuser = config.get('MySQL', 'dbuser')
        dbpass = config.get('MySQL', 'dbpass')
        dbname = config.get('MySQL', 'dbname')
        self.auth_query = config.get('MySQL', 'auth_query')
        self.user_query = config.get('MySQL', 'user_query')

        self.conn = MySQLdb.connect(host = dbhost,
                                    user = dbuser,
                                    passwd = dbpass,
                                    db = dbname)


    def __del__(self):
        self.conn.close()


    def auth(self, params):
        cursor = self.conn.cursor()
        query, values = expand_query(self.auth_query, params)
        cursor.execute(query, values)
        row = cursor.fetchone()
        cursor.close()

        # Only return true if there was a row result
        if row:
            return True
        return False


    def lookup(self, params):
        cursor = self.conn.cursor()
        query, values = expand_query(self.user_query, params)
        cursor.execute(query, values)
        row = cursor.fetchone()
        assert row, 'No results from select (invalid user?)'
        cursor.close()

        return row[0]


    def create_storage(self, params):
        return MysqlStorage(self.conn, self.params, self.config)
