#!/usr/bin/env python3

import os
import tempfile
import unittest
import urllib.request
import subprocess
import sys
from slicecap import Slicecap, PcapFileHeader, PcapPkthdr
import argparse

class TestSlicecap(unittest.TestCase):
    """Unit tests for slicecap functionality using sample pcap files from wireshark.org"""

    @classmethod
    def setUpClass(cls):
        """Download sample pcap files from wireshark.org for testing"""
        cls.test_dir = tempfile.mkdtemp()
        cls.pcap_files = {}

        # Sample pcap files from wireshark.org automated captures
        cls.sample_files = {
            'fuzz-2006-06-26-2594.pcap': 'https://www.wireshark.org/download/automated/captures/fuzz-2006-06-26-2594.pcap',
            'fuzz-2006-07-05-1209.pcap': 'https://www.wireshark.org/download/automated/captures/fuzz-2006-07-05-1209.pcap',
            'fuzz-2006-07-05-6279.pcap': 'https://www.wireshark.org/download/automated/captures/fuzz-2006-07-05-6279.pcap'
        }

        print("Downloading sample pcap files from wireshark.org...")
        for filename, url in cls.sample_files.items():
            try:
                local_path = os.path.join(cls.test_dir, filename)
                urllib.request.urlretrieve(url, local_path)
                cls.pcap_files[filename] = local_path
                print(f"Downloaded: {filename}")
            except Exception as e:
                print(f"Failed to download {filename}: {e}")

    @classmethod
    def tearDownClass(cls):
        """Clean up downloaded files"""
        import shutil
        if os.path.exists(cls.test_dir):
            shutil.rmtree(cls.test_dir)

    def test_pcap_file_header_parsing(self):
        """Test PcapFileHeader class with real pcap files"""
        for filename, filepath in self.pcap_files.items():
            with self.subTest(filename=filename):
                header = PcapFileHeader()
                with open(filepath, 'rb') as f:
                    header.unpack_header(f.read(24))

                # Basic validation
                self.assertIn(header.byte_order, ['!', '<'])
                self.assertGreater(header.snaplen, 0)
                self.assertGreaterEqual(header.network, 0)

    def test_pcap_pkthdr_parsing(self):
        """Test PcapPkthdr class with real pcap files"""
        for filename, filepath in self.pcap_files.items():
            with self.subTest(filename=filename):
                with open(filepath, 'rb') as f:
                    # Skip file header
                    f.seek(24)

                    # Read first packet header
                    pkthdr_data = f.read(16)
                    if len(pkthdr_data) == 16:
                        header = PcapFileHeader()
                        with open(filepath, 'rb') as f2:
                            header.unpack_header(f2.read(24))

                        pkthdr = PcapPkthdr()
                        pkthdr.unpack_header(pkthdr_data, header.byte_order)

                        # Basic validation
                        self.assertGreater(pkthdr.tv_sec, 0)
                        self.assertGreaterEqual(pkthdr.tv_usec, 0)
                        self.assertGreater(pkthdr.caplen, 0)

    def test_slicecap_initialization(self):
        """Test Slicecap class initialization with real pcap files"""
        for filename, filepath in self.pcap_files.items():
            with self.subTest(filename=filename):
                # Create mock options
                options = argparse.Namespace()
                options.infile = filepath
                options.nslice = 2
                options.maxgap = 3600

                try:
                    sc = Slicecap(options)
                    self.assertIsInstance(sc.file_header, PcapFileHeader)
                    self.assertGreater(sc.size, 0)
                except Exception as e:
                    self.fail(f"Slicecap initialization failed for {filename}: {e}")

    def test_slice_offset_calculation(self):
        """Test slice offset calculation with real pcap files"""
        for filename, filepath in self.pcap_files.items():
            with self.subTest(filename=filename):
                options = argparse.Namespace()
                options.infile = filepath
                options.nslice = 3
                options.maxgap = 3600

                try:
                    sc = Slicecap(options)
                    sc.guess_slice_offsets_and_sizes()

                    # Validate offsets and sizes
                    self.assertEqual(len(sc.offsets), options.nslice)
                    self.assertEqual(len(sc.sizes), options.nslice)

                    # All offsets should be >= 24 (after file header)
                    for offset in sc.offsets:
                        self.assertGreaterEqual(offset, 24)

                    # Sum of sizes should equal total file size minus first offset
                    total_slice_size = sum(sc.sizes)
                    expected_size = sc.size - sc.offsets[0] + 24  # Add back file header
                    self.assertAlmostEqual(total_slice_size, expected_size, delta=100)

                except Exception as e:
                    # Some files might be too small to slice
                    if "could not find pcap pkthdr" in str(e):
                        self.skipTest(f"File {filename} too small for slicing")
                    else:
                        self.fail(f"Slice calculation failed for {filename}: {e}")

    def test_slicecap_with_cat_command(self):
        """Test slicecap with a simple cat command that outputs to files"""
        for filename, filepath in self.pcap_files.items():
            with self.subTest(filename=filename):
                options = argparse.Namespace()
                options.infile = filepath
                options.nslice = 2
                options.maxgap = 3600
                options.npara = '1'  # Use single process for testing

                # Create output files for each slice
                output_files = []
                for i in range(options.nslice):
                    output_file = os.path.join(self.test_dir, f"{filename}_slice_{i}.pcap")
                    output_files.append(output_file)

                # Use cat to output slices to files
                options.subcmdargs = ['cat', '>', os.path.join(self.test_dir, f"{filename}_slice_{{SLICE_ID}}.pcap")]

                try:
                    sc = Slicecap(options)
                    sc.guess_slice_offsets_and_sizes()
                    sc.call_subcommands()

                    # Check that output files were created
                    for i, output_file in enumerate(output_files):
                        if os.path.exists(output_file):
                            # Verify the output file has pcap header
                            with open(output_file, 'rb') as f:
                                magic = f.read(4)
                                self.assertIn(magic, [b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1'])

                except Exception as e:
                    # Some files might be too small to slice
                    if "could not find pcap pkthdr" in str(e):
                        self.skipTest(f"File {filename} too small for slicing")
                    else:
                        self.fail(f"Slicecap execution failed for {filename}: {e}")

    def test_byte_order_detection(self):
        """Test byte order detection for different pcap files"""
        for filename, filepath in self.pcap_files.items():
            with self.subTest(filename=filename):
                header = PcapFileHeader()
                with open(filepath, 'rb') as f:
                    data = f.read(4)
                    if len(data) == 4:
                        # Test magic number detection
                        magic = tuple(data)
                        if magic == (0xa1, 0xb2, 0xc3, 0xd4):
                            expected_order = '!'
                        elif magic == (0xd4, 0xc3, 0xb2, 0xa1):
                            expected_order = '<'
                        else:
                            self.fail(f"Unknown magic number in {filename}: {magic}")

                        # Parse full header and verify byte order
                        f.seek(0)
                        header.unpack_header(f.read(24))
                        self.assertEqual(header.byte_order, expected_order)

def main():
    """Run the unit tests"""
    # Check if we can import slicecap
    try:
        import slicecap
    except ImportError:
        print("Error: Cannot import slicecap module. Make sure slicecap.py is in the Python path.")
        sys.exit(1)

    # Run tests
    unittest.main(verbosity=2)

if __name__ == '__main__':
    main()