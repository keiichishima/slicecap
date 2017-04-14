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
    '''The PcapFileHeader class keeps the information of the pcap file
    header information.

    '''
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
        '''Unpack the pcap file header passed as the data argument and set
        them to the internal variables.

        '''
        # Read first 4 bytes to determine the byte order of this pcap
        # data.
        self._magic = struct.unpack('4B', data[:4])
        if self._magic == (0xa1, 0xb2, 0xc3, 0xd4):
            self._byte_order = '!'
        elif self._magic == (0xd4, 0xc3, 0xb2, 0xa1):
            self._byte_order = '<'
        else:
            print('unknown magic id in the pcap file header.')
            raise ValueError
        # Read metadata of this pcap file.
        (self._version_major,
         self._version_minor,
         self._thiszone,
         self._sigfigs,
         self._snaplen,
         self._network) = struct.unpack(
             self._byte_order + '2Hl3L', data[4:])

        # Version 2.4 is the only version supported.
        if not (self._version_major == 2
                and self._version_minor ==4):
            print('pcap file version {0}.{1} unsupported'.format(
                self._version_major, self._version_minor))
            raise ValueError

        # The snaplen value is used when searching pcap pkthdr
        # to validate the caplen field.  If this is not specified,
        # maybe we need to set this value to the default value of the
        # max link layer frame size based on the type of link layer.
        if self._snaplen == 0:
            # XXX should set a max frame size based on the type of network
            self._snaplen = 9000

    def pack_header(self):
        '''Pack the pcap file header to a binary sequence.

        '''
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
    '''The PcapPkthdr class keeps the information of the pcap pkthdr
    information.

    '''
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
    '''The Slicecap class keeps the input pcap file information and user
    specified parameters required to slice and process data.  This
    class also provides some operation methods to decide offsets of
    sliced parts and trigger subprocesses.

    '''
    def __init__(self, options):
        self._file_header = PcapFileHeader()
        self._options = options
        self._size = os.stat(self._options.infile).st_size
        self._slice_size = self._size // self._options.nslice
        self._tv_sec_anchor = 0
        self._tv_usec_anchor = 0
        self._offsets = []
        self._sizes = []

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
        with open(self._options.infile, 'rb') as _pfo:
            self._file_header.unpack_header(_pfo.read(24))
            pph = PcapPkthdr()
            pph.unpack_header(_pfo.read(16),
                              self._file_header.byte_order)
            self._tv_sec_anchor = pph.tv_sec
            self._tv_usec_anchor = pph.tv_usec

    def guess_slice_offsets_and_sizes(self):
        '''Try to slice the source pcap file into N files specified by the
        command line parameter.  The offset and size values of each
        sliced fragment are stored in self._offsets and self._sizes
        arrays.

        '''
        with open(self._options.infile, 'rb') as _pfo:
            for _slice_id in range(self._options.nslice):
                _off = self._guess_offset_of_slice_id(_pfo, _slice_id)
                self._offsets.append(_off)
                if _slice_id > 0:
                    self._sizes.append(_off - self._offsets[_slice_id - 1])
            self._sizes.append(self._size - self._offsets[-1])

    def _guess_offset_of_slice_id(self, pfo, slice_id):
        # Seek the file pointer to guessed position.
        _pcap_off_guess = slice_id * self._slice_size
        pfo.seek(_pcap_off_guess, 0)

        # From the guessed position, read (snaplen + LLHDR len +
        # pcap_pkthdr len + margin) size data.  It must be enough long
        # to include the next pcap pkthdr data.
        data = pfo.read(self._file_header.snaplen + 1000)

        # Check if the file position is likely to match the pcap
        # pkthdr format by shifting the file pointer by 1 byte.
        for _off_diff in range(len(data) - 16):
            _pph = PcapPkthdr()
            _pph.unpack_header(data[_off_diff:_off_diff + 16],
                              self._file_header.byte_order)
            # If the timestamp value is smaller than the value seen
            # previously, skip.
            if _pph.tv_sec < self._tv_sec_anchor:
                continue
            # If the difference of this timestamp value and the value
            # seen before is grater than the maxgap value, skip.
            if _pph.tv_sec - self._tv_sec_anchor > self._options.maxgap:
                continue
            # If the caplen value is greater than the snaplen value,
            # skip.
            if _pph.caplen > self._file_header.snaplen:
                continue
            # If the len value is greater than the maximum media frame
            # size, skip.
            #if _pph.len > MAX_LINK_FRAME_SIZE:
            #    continue
            #
            # XXX check frame contents for better validation

            # Update the time anchor.
            self._tv_sec_anchor = _pph.tv_sec
            self._tv_usec_anchor = _pph.tv_usec

            # Return the guessed offset.
            return _pcap_off_guess + _off_diff

        # Failed to find a pcap pkthdr.
        print('could not find pcap pkthdr at slice_id={}'.format(slice_id))
        raise ValueError

    def call_subcommands(self):
        if self._options.npara == 'auto':
            _npara = None
        else:
            _npara = int(self._options.npara)
        with multiprocessing.Pool(_npara) as _pool:
            _pool.map(func=self._call_subcommand_for_slice_id,
                      iterable=range(len(self._offsets)))

    def _call_subcommand_for_slice_id(self, slice_id):
        # Replace slice dependent variables specified by the user
        # to actual values.
        _offset = self._offsets[slice_id]
        _size = self._sizes[slice_id]
        _subcmd = ' '.join([w.format(OFFSET=_offset,
                                     SIZE=_size,
                                     SLICE_ID=slice_id)
                            for w in self._options.subcmdargs])

        _proc = subprocess.Popen(_subcmd,
                                 stdin=subprocess.PIPE,
                                 shell=True)

        _proc.stdin.write(self._file_header.pack_header())
        with open(self._options.infile, 'rb') as _pfo:
            _pfo.seek(_offset)
            _data_left = _size
            while _data_left > 0:
                if _data_left > 8192:
                    _data = _pfo.read(8192)
                else:
                    _data = _pfo.read(_data_left)
                _proc.stdin.write(_data)
                _data_left -= len(_data)
        _proc.stdin.flush()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--maxgap', type=int, dest='maxgap',
                        default=3600,
                        help='maximum packet interval for pcap pkthdr gap validation')
    parser.add_argument('-n', '--number', type=int, dest='nslice',
                        default=2,
                        help='number of sliced fragments')
    parser.add_argument('-p', '--parallel', type=str, dest='npara',
                        default='auto',
                        help='maximum number of parallel processes')
    parser.add_argument('-r', '--infile', type=str, dest='infile',
                        required=True,
                        help='source pcap file')
    parser.add_argument('subcmdargs', type=str, nargs='+',
                        help='subprocess specification')
    options = parser.parse_args()

    sc = Slicecap(options)
    sc.guess_slice_offsets_and_sizes()
    sc.call_subcommands()

if __name__ == '__main__':
    main()
