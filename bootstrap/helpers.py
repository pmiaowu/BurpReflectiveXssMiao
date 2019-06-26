#!/usr/bin/python
# -*- coding: utf-8 -*-

def addslashes(s):
    d = {'"':'\\"', "'":"\\'", "\0":"\\\0", "\\":"\\\\"}
    return ''.join(d.get(c, c) for c in s)

def htmlspecialchars(s, t = 'ENT_COMPAT'):
    d = {'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', '\'':'&#039;'}
    if t == 'ENT_COMPAT':
        del d['\'']
    elif t == 'ENT_QUOTES':
        pass
    elif t == 'ENT_NOQUOTES':
        del d['\'']
        del d['"']
    else:
        del d['\'']
    return ''.join(d.get(c, c) for c in s)