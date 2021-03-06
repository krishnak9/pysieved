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
import MySQLdb.constants.CR
import re

import __init__


expand_names = (
    'username',
    'password',
    'name',
    'script',
)

expand_re_str = '%\((' + '|'.join(expand_names) + ')\)s|' + \
                '"%\((' + '|'.join(expand_names) + ')\)s"|' + \
                '\'%\((' + '|'.join(expand_names) + ')\)s\''

expand_re = re.compile(expand_re_str)


def expand_query(query, params):
    values = []
    for match in expand_re.finditer(query):
        sub = match.group().replace('"', '').replace('\'', '')
        values.append(params[sub[2:-2]])

    query = re.sub(expand_re, '%s', query)

    return (query, values)


class MysqlConnection:
    def __init__(self, log, dbhost, dbuser, dbpass, dbname):
        self.log = log
        self.dbhost = dbhost
        self.dbuser = dbuser
        self.dbpass = dbpass
        self.dbname = dbname
        self.conn = None


    def __del__(self):
        if self.conn:
            try:
                self.conn.close()
            except:
                pass

        self.conn = None


    def connect(self):
        self.log(5, 'connecting to database %s on %s' % (self.dbname, self.dbhost))
        try:
            self.conn = MySQLdb.connect(host = self.dbhost,
                                        user = self.dbuser,
                                        passwd = self.dbpass,
                                        db = self.dbname)
            self.log(5, 'connected to database %s on %s' % (self.dbname, self.dbhost))
            return True
        except MySQLdb.MySQLError, e:
            self.conn = None
            self.log(5, 'failed connection to database %s on %s: %s' % (self.dbname, self.dbhost, str(e)))
            return False


    def demand_connect(self):
        if self.conn is None:
            return self.connect()

        try:
            self.conn.ping()
        except MySQLdb.MySQLError, e:
            if e[0] == MySQLdb.constants.CR.SERVER_GONE_ERROR:
                self.log(5, 'lost connection to database %s on %s' % (self.dbname, self.dbhost))
                return self.connect()

            return False

        return True


    def cursor(self):
        if self.demand_connect():
            return self.conn.cursor()
        else:
            raise RuntimeError('not connected to database')


    def close():
        if self.conn:
            try:
                self.conn.close()
            except:
                pass

        self.conn = None


class MysqlStorage(__init__.ScriptStorage):
    def __init__(self, log, conn, params, config):
        self.log = log
        self.conn = conn
        self.params = params
        self.list_query = config.get('MySQL', 'list_query')
        self.get_query = config.get('MySQL', 'get_query')
        self.update_query = config.get('MySQL', 'update_query')
        self.insert_query = config.get('MySQL', 'insert_query')
        self.delete_query = config.get('MySQL', 'delete_query')
        self.active_query = config.get('MySQL', 'active_query')
        self.set_active_query = config.get('MySQL', 'set_active_query')
        self.clear_active_query = config.get('MySQL', 'clear_active_query')


    def expand_query(self, query, params):
        self.log(9, 'expand_query input: %s / %r' % (query, params))
        query, values = expand_query(query, params)
        self.log(9, 'expand_query output: %s / %r' % (query, values))
        return (query, values)


    def __iter__(self):
        query, values = self.expand_query(self.list_query,
                                          dict(self.params))
        cursor = self.conn.cursor()
        cursor.execute(query, values)
        results = cursor.fetchall()
        for row in results:
            if row:
                yield row[0]
            else:
                break


    def has_key(self, k):
        query, values = self.expand_query(self.get_query,
                                          dict(self.params,
                                               name = k))
        cursor = self.conn.cursor()
        cursor.execute(query, values)
        if cursor.fetchone():
            return True
        return False


    def __getitem__(self, k):
        if k != None and not self.has_key(k):
            raise KeyError('Unknown script')
        query, values = self.expand_query(self.get_query,
                                          dict(self.params,
                                               name = k))
        cursor = self.conn.cursor()
        cursor.execute(query, values)
        row = cursor.fetchone()
        return row[0]


    def __setitem__(self, k, v):
        if self.has_key(k):
            query, values = self.expand_query(self.update_query,
                                              dict(self.params,
                                                   name = k,
                                                   script = v))
        else:
            query, values = self.expand_query(self.insert_query,
                                              dict(self.params,
                                                   name = k,
                                                   script = v))
        cursor = self.conn.cursor()
        cursor.execute(query, values)


    def __delitem__(self, k):
        if self.is_active(k):
            raise ValueError('Script is active')
        query, values = self.expand_query(self.delete_query,
                                          dict(self.params,
                                               name = k))
        cursor = self.conn.cursor()
        cursor.execute(query, values)


    def get_active(self):
        query, values = self.expand_query(self.active_query,
                                          dict(self.params))
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
            self.log(5, 'Set active %s' % k)
            if not self.has_key(k):
                self.log(5, 'No script named %s' % k)
                raise KeyError('Unknown script')
            self.log(7, 'Found script %s' % k)
        else:
            self.log(5, 'Set active None')

        self.log(7, 'Clearing active script')
        query, values = self.expand_query(self.clear_active_query,
                                          dict(self.params))
        cursor = self.conn.cursor()
        cursor.execute(query, values)
        self.log(7, 'Done clearing active script')

        if k:
            self.log(7, 'Activating %s' % k)
            query, values = self.expand_query(self.set_active_query,
                                              dict(self.params,
                                                   name = k))
            cursor = self.conn.cursor()
            cursor.execute(query, values)
            self.log(7, 'Done activating %s' % k)

        self.log(5, 'Done set active')


class PysievedPlugin(__init__.PysievedPlugin):
    def init(self, config):
        dbhost = config.get('MySQL', 'dbhost')
        dbuser = config.get('MySQL', 'dbuser')
        dbpass = config.get('MySQL', 'dbpass')
        dbname = config.get('MySQL', 'dbname')
        self.auth_query = config.get('MySQL', 'auth_query')
        self.user_query = config.get('MySQL', 'user_query')
        self.config = config

        self.conn = MysqlConnection(self.log, dbhost, dbuser, dbpass, dbname)


    def __del__(self):
        self.conn.close()


    def expand_query(self, query, params):
        self.log(9, 'expand_query input: %s / %r' % (query, params))
        query, values = expand_query(query, params)
        self.log(9, 'expand_query output: %s / %r' % (query, values))
        return (query, values)


    def auth(self, params):
        cursor = self.conn.cursor()
        query, values = self.expand_query(self.auth_query, params)
        cursor.execute(query, values)
        row = cursor.fetchone()
        cursor.close()

        # Only return true if there was a row result
        if row:
            return True
        return False


    def lookup(self, params):
        cursor = self.conn.cursor()
        query, values = self.expand_query(self.user_query, params)
        cursor.execute(query, values)
        row = cursor.fetchone()
        assert row, 'No results from select (invalid user?)'
        cursor.close()

        return row[0]


    def create_storage(self, params):
        return MysqlStorage(self.log, self.conn, params, self.config)
