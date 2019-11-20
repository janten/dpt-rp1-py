#!/usr/bin/env python3
"""
Usage
-----

> dptmount /mnt/mymountpoint


Config file
------------

A simple yaml such as

> dptrp1:
>   client-id: ~/.config/dpt/deviceid.dat
>   key: ~/.config/dpt/privatekey.dat
>   addr: 192.168.0.200

Todo
----

* Main thing is to allow for writing/uploading
* Also, a reasonable and robust caching is needed
* Rename/Move should be possible in the near future

Author
------

Juan Grigera <juan@grigera.com.ar>

upload functionality by Jochen Schroeder <cycomanic@gmail.com>
"""

# debian-dependency: python3-fusepy
# pip3 install fusepy

import os
import sys
import errno
import time
import calendar
import yaml
import io
from errno import ENOENT, EACCES
from stat import S_IFDIR, S_IFLNK, S_IFREG

import logging

logger = logging.getLogger("dptmount")

try:
    from fuse import FUSE, FuseOSError, Operations, LoggingMixIn
except ModuleNotFoundError:
    from fusepy import FUSE, FuseOSError, Operations, LoggingMixIn
from dptrp1.dptrp1 import DigitalPaper, find_auth_files

import anytree

class FileHandle(object):

    def __init__(self, fs, local_path, new=False):
        self.fs = fs
        dpath, fname = os.path.split(local_path)
        self.parent = self.fs._map_local_remote(dpath)
        self.remote_path = os.path.join(self.parent.remote_path, fname)
        if new:
            self.status = "clean"
        else:
            node = self.fs._map_local_remote(local_path)
            assert self.remote_path == node.item['entry_path']
            self.status = "unread"
        self.data = bytearray()

    def read(self, length, offset):
        if self.status == "unread":
            logger.info('Downloading %s', self.remote_path)
            self.status = "clean"
            self.data = self.fs.dpt.download(self.remote_path)
        return self.data[offset:offset + length]

    def write(self, buf, offset):
        self.status = "dirty"
        self.data[offset:] = buf
        return len(buf)

    def flush(self):
        if self.status != "dirty":
            return
        stream = io.BytesIO(self.data)
        self.fs.dpt.upload(stream, self.remote_path)
        # XXX do we sometimes need to remove an old node?
        self.fs._add_remote_path_to_tree(self.parent, self.remote_path) # TBI
        self.status = "clean"

class DptTablet(LoggingMixIn, Operations):
    def __init__(
        self,
        dpt_ip_address=None,
        dpt_serial_number=None,
        dpt_key=None,
        dpt_client_id=None,
        uid=None,
        gid=None,
    ):
        self.dpt_ip_address = dpt_ip_address
        self.dpt_serial_number = dpt_serial_number
        self.dpt_key = os.path.expanduser(dpt_key)
        self.dpt_client_id = os.path.expanduser(dpt_client_id)
        self.uid = uid
        self.gid = gid
        self.__authenticate__()

        # Create root node
        self.__init_empty_tree()

        # Cache this for the session
        logger.info("Loading initial document list")
        self._load_document_list()
        logger.debug(anytree.RenderTree(self.root))

        self.handle = {}
        self.files = {}
        self.fd = 0

    def __init_empty_tree(self):
        # Create root node
        self.now = time.time()
        self.root = anytree.Node('Document', item = None, localpath='/',
                         remote_path="Document",
                         lstat=dict(st_mode=(S_IFDIR | 0o755),
                                    st_ctime=self.now,
                                    st_mtime=self.now,
                                    st_atime=self.now,
                                    st_nlink=2), )

    def __authenticate__(self):
        self.dpt = DigitalPaper(self.dpt_ip_address, self.dpt_serial_number)

        with open(self.dpt_client_id) as fh:
            client_id = fh.readline().strip()

        with open(self.dpt_key, "rb") as fh:
            key = fh.read()

        self.dpt.authenticate(client_id, key)

    def _remove_node(self, node):
        node.parent = None
        del node

    def _add_node_to_tree(self, parent, item):
        return anytree.Node(
            item["entry_name"],
            parent=parent,
            item=item,
            remote_path=item["entry_path"],
            lstat=self._get_lstat(item),
            localpath=os.path.join(parent.localpath, item["entry_name"]),
        )

    def _add_remote_path_to_tree(self, parent, remote_path):
        item = self.dpt._resolve_object_by_path(remote_path)
        return self._add_node_to_tree(parent, item)

    def _load_document_list(self):
        # TODO maybe some smarter caching?
        self._recurse_load_document_list(self.root)

    def _recurse_load_document_list(self, parent):
        parentnodepath = "/".join([str(node.name) for node in parent.path])

        for item in self.dpt.list_objects_in_folder(parentnodepath):
            node = self._add_node_to_tree(parent, item)
            if item["entry_type"] == "folder":
                self._recurse_load_document_list(node)

    def _get_lstat(self, item):
        if "reading_date" in item:
            atime = calendar.timegm(
                time.strptime(item["reading_date"], "%Y-%m-%dT%H:%M:%SZ")
            )
        else:
            # access time = now if never read...
            atime = self.now

        lstat = dict(
            st_atime=atime,
            st_gid=self.gid,
            st_uid=self.uid,
            st_ctime=calendar.timegm(
                time.strptime(item["created_date"], "%Y-%m-%dT%H:%M:%SZ")
            ),
        )

        # usual thing for directories is st_link keeps number of subdirectories
        if item["entry_type"] == "folder":
            lstat["st_nlink"] = 2
            # todo: increment nlink in parent dir
            lstat["st_mode"] = S_IFDIR | 0o755
            lstat["st_mtime"] = self.now
        else:
            lstat["st_mode"] = S_IFREG | 0o644
            lstat["st_mtime"] = calendar.timegm(
                time.strptime(item["modified_date"], "%Y-%m-%dT%H:%M:%SZ")
            )
            lstat["st_nlink"] = 1
            lstat["st_size"] = int(item["file_size"])

            #'st_inot': item['entry_id'], 'entry_id': 'fe13e1df-1cfe-4fe3-9e83-3e12e78b8a47',

        # 'entry_name': '10.1017.pdf', 'entry_path': 'Document/10.1017.pdf', 'entry_type': 'document',
        # 'file_revision': 'a21ea4b1c368.2.0',
        # 'is_new': 'false', 'mime_type': 'application/pdf',
        # 'title': 'untitled', 'total_page': '4'}
        return lstat

    def _map_local_remote(self, full_local):
        return anytree.search.find(
            self.root, filter_=lambda node: node.localpath == full_local
        )

    def _is_read_only_flags(self, flags):
        # from pcachefs
        access_flags = os.O_RDONLY | os.O_WRONLY | os.O_RDWR
        return flags & access_flags == os.O_RDONLY

    # Filesystem methods
    # ==================
    def chmod(self, path, mode):
        # TODO: should support chown/chmod
        return 0

    def chown(self, path, uid, gid):
        # TODO: should support chown/chmod
        return 0

    def getattr(self, path, fh=None):
        if path in self.files:
            return self.files[path]
        node = self._map_local_remote(path)
        if node is None:
            raise FuseOSError(ENOENT)
        return node.lstat

    def readdir(self, path, fh):
        node = self._map_local_remote(path)
        entries = node.children

        dirents = [".", ".."]
        dirents.extend([e.name for e in entries])
        logger.debug(dirents)
        return dirents

    def unlink(self, path):
        node = self._map_local_remote(path)
        remote_path = node.remote_path
        data = self.dpt.delete_document(node.remote_path)
        self._remove_node(node)
        return 0

    # Directory creation
    # ============
    def rmdir(self, path):
        node = self._map_local_remote(path)
        self.dpt.delete_folder(node.remote_path)
        self._remove_node(node)
        return 0

    def mkdir(self, path, mode):
        ppath, dirname = os.path.split(path)
        parent = self._map_local_remote(ppath)
        remote_path = os.path.join(parent.remote_path, dirname)
        self.dpt.new_folder(remote_path)
        node = self._add_remote_path_to_tree(parent, remote_path)
        return 0

    # File methods
    # ============
    def open(self, path, flags):
        if not self._is_read_only_flags(flags):
            return FuseOSError(EACCES)
        self.fd += 1
        self.handle[self.fd] = FileHandle(self, path, new=False)
        logger.info('file handle %d opened' % self.fd)
        return self.fd

    def release(self, path, fh):
        # TODO: something is going wrong with releasing the file handles for new created docs
        logger.info("file handle %d closed" % fh)
        node = self._map_local_remote(path)
        del self.handle[fh]
        return 0

    def read(self, path, length, offset, fh):
        return self.handle[fh].read(length, offset)

    def rename(self, oldpath, newpath):
        old_node = self._map_local_remote(oldpath)
        new_folder, fname = os.path.split(newpath)
        new_folder_node = self._map_local_remote(new_folder)
        newpath = os.path.join(new_folder_node.remote_path, fname)
        self.dpt.rename_document(old_node.remote_path, newpath)
        self._remove_node(old_node)
        self._add_remote_path_to_tree(new_folder_node, newpath)

    def create(self, path, mode, fi=None):
        #TODO: check if files is necessary
        logger.debug("create path {}".format(path))
        self.files[path] = dict(
            st_mode=(S_IFREG | mode),
            st_nlink=1,
            st_size=0,
            st_ctime=time.time(),
            st_mtime=time.time(),
            st_atime=time.time(),
        )

        self.fd += 1
        self.handle[self.fd] = FileHandle(self, path, new=True)
        return self.fd

    def write(self, path, buf, offset, fh):
        return self.handle[fh].write(buf, offset)

    def flush(self, path, fh):
        self.handle[fh].flush()
        self.files.pop(path, None)

YAML_CONFIG_PATH = os.path.expanduser("~/.config/dpt-rp1.conf")


def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("mountpoint")

    parser.add_argument(
        "--config",
        default=YAML_CONFIG_PATH,
        help="config file, default is %s" % YAML_CONFIG_PATH,
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument(
        "--logfile",
        default=False,
        help="Log to a file (default: log to standard output)",
    )
    parser.add_argument("--big_writes", default=True, help="Enable writes of big")
    args = parser.parse_args()
    kwarg = ["big_writes"]
    kwargs = {}
    for k in kwarg:
        kwargs[k] = getattr(args, k)

    # Set up logging
    if args.logfile is False:
        logging.basicConfig()
    else:
        logging.basicConfig(filename=args.logfile)

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    # Read YAML config if found
    if os.path.isfile(args.config):
        config = yaml.safe_load(open(args.config, "r"))
    else:
        print("Config file not found")
        sys.exit(-1)

    # config
    dpt_client_id, dpt_key = find_auth_files()
    cfgargs = config["dptrp1"]
    params = dict(
        dpt_ip_address=cfgargs.get("addr", None),
        dpt_serial_number=cfgargs.get("serial", None),
        dpt_client_id=cfgargs.get("client-id", dpt_client_id),
        dpt_key=cfgargs.get("key", dpt_key),
        uid=os.getuid(),
        gid=os.getgid(),
    )

    tablet = DptTablet(**params)
    fuse = FUSE(
        tablet,
        args.mountpoint,
        foreground=True,
        allow_other=True,
        nothreads=True,
        **kwargs
    )


if __name__ == "__main__":
    main()
