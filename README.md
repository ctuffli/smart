# README #

### What is this repository for? ###

* Application to output the SMART values of disks
* Version 0.0.3

### How do I get set up? ###

* Clone this repository onto a FreeBSD box and run make

    $ hg clone https://ctuffli@bitbucket.org/ctuffli/smart
    $ cd smart && make

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
page. The application outputs:
    <Log Page ID> <Attribute ID> <Attribute value>
for each selected attribute.