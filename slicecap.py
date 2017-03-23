#!/usr/bin/env python

from __future__ import print_function
from __future__ import unicode_literals
from builtins import bytes
from builtins import str

import argparse
import multiprocessing
import os
import struct
import subprocess

class PcapFileHeader(object):
    def __init__(self):
        self._byte_order = '!'
        self._version_major = 0
        self._version_minor = 0
        self._thiszone = 0
        self._sigfigs = 0
        self._snaplen = 0
        self._network = 0

    @property
    def byte_order(self):
        return self._byte_order

    @property
    def snaplen(self):
        return self._snaplen

    @property
    def network(self):
        return self._network

    def unpack_header(self, data):
        self._magic = struct.unpack('4B', data[:4])
        if self._magic == (0xa1, 0xb2, 0xc3, 0xd4):
            self._byte_order = '!'
        elif self._magic == (0xd4, 0xc3, 0xb2, 0xa1):
            self._byte_order = '<'
        else:
            print('unknown magic id in the pcap file header.')
            raise ValueError
        (self._version_major,
         self._version_minor,
         self._thiszone,
         self._sigfigs,
         self._snaplen,
         self._network) = struct.unpack(
             self._byte_order + '2Hl3L', data[4:])

        if not (self._version_major == 2
                and self._version_minor ==4):
            print('pcap file version {0}.{1} unsupported'.format(
                self._version_major, self._version_minor))
            raise ValueError

        # is this needed?
        if self._snaplen == 0:
            # XXX should set a max frame size based on the type of network
            self._snaplen = 9000

    def pack_header(self):
        return struct.pack(self._byte_order + '4B2Hl3L',
                           self._magic[0],
                           self._magic[1],
                           self._magic[2],
                           self._magic[3],
                           self._version_major,
                           self._version_minor,
                           self._thiszone,
                           self._sigfigs,
                           self._snaplen,
                           self._network)

class PcapPkthdr(object):
    def __init__(self):
        self._tv_sec = 0
        self._tv_usec = 0
        self._caplen = 0
        self._len = 0

    @property
    def tv_sec(self):
        return self._tv_sec

    @property
    def tv_usec(self):
        return self._tv_usec

    @property
    def caplen(self):
        return self._caplen

    def unpack_header(self, data, byte_order):
        (self._tv_sec,
         self._tv_usec,
         self._caplen,
         self._len) = struct.unpack(
             byte_order + '4L', data)
       
class Slicecap(object):
    def __init__(self, options):
        self._file_header = PcapFileHeader()
        self._options = options
        self._size = os.stat(self._options.infile).st_size
        self._frag_size = self._size // self._options.nsplit
        self._base_tv_sec = 0
        self._base_tv_usec = 0
        self._offsets = []
        self._sizes = []

        self._fo = open(self._options.infile, 'rb')
        self._unpack_file_header()

    @property
    def file_header(self):
        return self._file_header

    @property
    def options(self):
        return self._options

    @property
    def size(self):
        return self._size

    @property
    def offsets(self):
        return self._offsets
       
    @property
    def sizes(self):
        return self._sizes
       
    def _unpack_file_header(self):
        self._file_header.unpack_header(self._fo.read(24))
        pph = PcapPkthdr()
        pph.unpack_header(self._fo.read(16),
                          self._file_header.byte_order)
        self._base_tv_sec = pph.tv_sec
        self._base_tv_usec = pph.tv_usec

    def get_offset_of_frag_id(self, frag_id):
        _pcap_off_guess = frag_id * self._frag_size
        self._fo.seek(_pcap_off_guess, 0)
        # read snaplen + LLHDR len + pcap_pkthdr len + margin
        data = self._fo.read(self._file_header.snaplen + 1000)
        for _off_diff in range(len(data) - 4):
            pph = PcapPkthdr()
            pph.unpack_header(data[_off_diff:_off_diff + 16],
                              self._file_header.byte_order)
            if pph.tv_sec < self._base_tv_sec:
                continue
            if pph.tv_sec - self._base_tv_sec > self._options.maxgap:
                continue
            if pph.caplen > self._file_header.snaplen:
                continue
            #if pph.len > MAX_LINK_FRAME_SIZE:
            #    continue
            # XXX check frame contents for better validation
            return _pcap_off_guess + _off_diff
        raise ValueError

def call_subcommand(splitcap, frag_id):
    _offset = splitcap.offsets[frag_id]
    _size = splitcap.sizes[frag_id]
    _subcmd = ' '.join([w.format(OFFSET=_offset,
                                 SIZE=_size,
                                 FRAG_ID=frag_id)
                        for w in splitcap.options.subcmdargs])
    _proc = subprocess.Popen(_subcmd,
                             stdin=subprocess.PIPE,
                             shell=True)
    
    _proc.stdin.write(splitcap.file_header.pack_header())
    with open(splitcap.options.infile, 'rb') as _pfo:
        _pfo.seek(_offset)
        _data_left = _size
        while _data_left > 0:
            _data = _pfo.read(8192)
            _proc.stdin.write(_data)
            _data_left -= len(_data)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--maxgap', type=int, dest='maxgap',
                        default=3600)
    parser.add_argument('-n', '--number', type=int, dest='nsplit',
                        default=2)
    parser.add_argument('-r', '--infile', type=str, dest='infile',
                        required=True)
    parser.add_argument('subcmdargs', type=str, nargs='+')
    options = parser.parse_args()

    sc = Slicecap(options)
    for _frag_id in range(sc.options.nsplit):
        off = sc.get_offset_of_frag_id(_frag_id)
        sc.offsets.append(off)
        if _frag_id > 0:
            sc.sizes.append(off - sc.offsets[_frag_id - 1])
    sc.sizes.append(sc.size - sc.offsets[-1])

    jobs = []
    for _frag_id in range(sc.options.nsplit):
        j = multiprocessing.Process(
            target=call_subcommand,
            args=(sc, _frag_id))
        jobs.append(j)
        j.start()
    for j in jobs:
        j.join()
        
    
if __name__ == '__main__':
    main()
