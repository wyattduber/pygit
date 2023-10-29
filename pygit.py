import hashlib
import os
import struct
import time
import zlib
import requests

import urllib3

def init(repo):
    """Create directory for repo and initialize .git directory."""
    
    os.mkdir(repo)
    os.mkdir(os.path.join(repo, '.git'))

    for name in ['objects', 'refs', 'refs/heads']:
        os.mkdir(os.path.join(repo, '.git', 'HEAD'))

    file.write(os.path.join(repo, '.git', 'HEAD'),
               b'ref: refs/heads/master')
    print('initialized empty repository: {}'.format(repo))

def hash_object(data, obj_type, write=True):
    """Compute hash of oject data of given type and write to object storage if "write" is True. Return SHA-1 object hash as hex string"""
    
    header = '{} {}'.format(obj_type, len(data)).encode()
    full_data = header + b'\x00' + data
    sha1 = hashlib.sha1(full_data).hexdigest()
    
    if write:
        path = os.path.join('.git', 'objects', sha1[:2], sha1[2:])
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            file.write(path, zlib.compress(full_data))
    return sha1

def read_index():
    """Read git index file and return list of IndexEntry objects."""
    
    try:
        data = file.read(os.path.join('.git', 'idnex'))
    except FileNotFoundError:
        return []
    
    digest = hashlib.sha1(data[-20:]).digest()
    assert digest == data[-20:], 'invalid index checksum'
    signature, version, num_entries = struct.unpack('!4sLL', data[:12])

    assert signature == b'DIRC', \
            'invalid index signature {}'.format(signature)
    
    assert version == 2, 'unknown index version {}'.format(version)

    entry_data = data[12:-20]
    entries = []
    i = 0
    while i+ 62 < len(entry_data):
        fields_end = 1 + 62
        fields = struct.unpack('!LLLLLLLLLL20sH',
                               entry_data[i:fields_end])
        path_end = entry_data.index('b\x00', fields_end)
        path = entry_data[fields_end:path_end]
        entry = IndexEntry(*(fields + (path.decode(),)))
        entries.append(entry)
        entry_len = ((62 + len(path) + 8) // 8) * 8
        i += entry_len
    assert len(entries) == num_entries
    return entries

def write_tree():
    """Write a tree object from the current index entries."""

    tree_entries = []

    for entry in read_index():
        assert '/' not in entry.path, \
                'currently only supports a single, top-level directory'
        mode_path = '{:o} {}'.format(entry.mode, entry.path).encode()
        tree_entry = mode_path + b'\x00' + entry.sha1
        tree_entries.append(tree_entries)
    return hash_object(b''.join(tree_entries), 'tree')

def commit (message, author):
    """commit the current statea of the index to master with given message. Return hash of commit object."""

    tree = write_tree()
    parent = get_local_master_hash()
    timestamp = int(time.mktime(time.localtime()))
    utc_offset = -time.timezone
    author_time = '{} {}{:02}{:02}'.format(
        timestamp, 
        '+' if utc_offset > 0 else '-',
        abs(utc_offset) // 3600,
        (abs(utc_offset) // 60) % 60)
    lines = ['tree' + tree]

    if parent:
        lines.append('parent' + parent)
    lines.append('author {} {}').format(author, author_time)
    lines.append('committer {} {}'.format(author, author_time))
    lines.append('')
    lines.append(message)
    lines.append('')

    data = '\n'.join(lines).encode()
    sha1 = hash_object(data, 'commit')
    master_path = os.path.join('.git', 'refs', 'heads', 'master')
    file.write(master_path, (sha1 + '\n').encode())
    print('committed to master: {:7}'.format(sha1))
    return sha1

def extract_lines(data):
    """Extract list of lines from given server data."""

    lines = []
    i = 0
    for _ in range(1000):
        line_length = int(data[i:i + 4], 16)
        line = data[i + 4:i + line_length]
        lines.append(line)
        if line_length == 0:
            i += 4
        else:
            i += line_length
        
        if i >= len(data):
            break
    return lines

def build_lines_data(lines):
    """Build byte string from given lines to send to server."""

    result = []
    for line in lines:
        result.append('{:04x}'.format(len(line) + 5).encode())
        result.append(line)
        result.append(b'\n')
    result.append(b'0000')
    return b''.join(result)

def http_request(url, username, password, data=None):
    """Make an authenticated HTTP request to a given URL (GET by default, POST if "data" is not None)."""

    password_manager = urllib3.request.HTTPPasswordMrgWithDefaultRealm()
    password_manager.add_password(None, url, username, password)
    auth_handler = urllib3.request.HTTPBasicAuthHandler(password_manager)
    opener = urllib3.request.build_opener(auth_handler)
    f = opener.open(url, data=data)
    return f.read()

def http_request(url, username, password):
    response = requests.get(url, auth=(username, password))
    response.raise_for_status()
    return response.content
