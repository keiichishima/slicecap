# Slice a large pcap file and process in parallel

## Install

    python setup.py install

## Usage

The below is an example to split a pcap file into 10 files.

    slicecap -r source.pcap -n 10 -- "cat > dest-{FRAG_ID}.pcap"

The `-r` or `--infile` option specifies input pcap file to slice.
Stdin is not acceptable because `slicecap` will change file handle
pointer using the `seek()` method.

The `-n` or `--number` option specifies the total number of splitted
pcap files.  This default value is 2.

The `-g` or `--maxgap` option specifies the maximum time difference
(in seconds) used to compare packet timestamps to find the pcap pkthdr
boundary.  The default value is 3600.

After the `--` option, you can specify a subprocess to process the
splitted pcap data.  In the above example, the splitted data will just
redirected into files.  In the subprocess definition, you can use the
following keywords that are replaced dynamically when executed.  Since
the replacement will be done by the Python text formatting function,
you can specify formatting rules using the standard Python text
formatter syntax.

- `OFFSET`: The file offset value in bytes.
- `SIZE`: The size of the pcap data part.
- `FRAG_ID`: The ID number (begins from 0) of the splitted files.


## Bug Reports
Please submit bug reports or patches through the GitHub interface.

## Author
Keiichi SHIMA
/ IIJ Innovation Institute Inc.
/ WIDE project
