# README #

### What is this repository for? ###

* Application to output the SMART values of disks

### How do I get set up? ###

Clone this repository onto a FreeBSD box and run make

    $ hg clone https://ctuffli@bitbucket.org/ctuffli/smart
    or
    $ git clone https://github.com/ctuffli/smart
    $ cd smart && make

or install it from ports ( http://www.freshports.org/sysutils/smart/ )

### How to use
    Usage: smart [-htxi] [-a <attribute id>] <device name>
            -h, --help
            -t, --threshold : also print out the threshold values
            -x, --hex : print the values out in hexadecimal
            -a, --attribute : print a specific attribute
            -i, --info : print general device information
            -v, --version : print the version and copyright

### Example
* List the raw attributes of SATA device /dev/ada0

        smart ada0

### What does the output mean?
The format and location of SMART / health data varies across protocols.
To simplify the output, the application uses a Dumb Unified Model of
SMART Buffers. In this model, SMART data is located in one or more log
pages. Each page contains one or more values ("attributes")
differentiated by an ID. Note that ID's are only unique within a log
page. Thus, the application outputs:

    <Log Page ID> <Attribute ID> <Attribute value>
for each selected attribute.

See the shell scripts `atasmart`, `nvmesmart`, and `scsismart` for examples of parsing the output.

### Protocol Specific Notes
* __ATA__ : The attribute and values follow the 'standard'. The log page is the Feature value used in ATA command. Thus, the default page is 0xd0 (a.k.a SMART Read Data). 
* __NVMe__ : The Log Page is the SMART / Health Information LID value in the Get Log Page command (i.e. 0x2). The attribute ID is the byte offset within this page.
* __SCSI__ : The Log Page ID is the Page Code value in the Mode Sense command. The attribute ID is the parameter code defined by this page (e.g. 0 in the Write Error Counters log page is 'Errors corrected without substantial delay'). The values will depend on the Page Codes supported by a drive.
