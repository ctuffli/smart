# README #

### What is this repository for? ###

* Application to output the SMART values of ATA disks
* Version 0.0.2

### How do I get set up? ###

* Clone this repository onto a FreeBSD box and run make

### How to use
    Usage: smart [-htxi] [-a <attribute id>]
            -h, --help
            -t, --threshold : also print out the threshold values
            -x, --hex : print the values out in hexadecimal
            -a, --attribute : print a specific attribute
            -i, --info : print general device information