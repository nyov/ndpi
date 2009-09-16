Compilation of the OpenDPI library and usage of the OpenDPI demonstration application

Prerequisites: 
	- the provided makefile and the demonstration application are intended for use with Linux and have been tested with
	  32-bit and 64-bit x86 Linux systems
	- the gcc C-Compiler
	- the make tool
	- the pcap library and its development files

Compilation:
	- change to the directory the OpenDPI.tar.gz file extracted to (the directory where this Readme file is located)
	- invoke the make command
	- after successful compilation there will be a libOpenDPI.a static library and the OpenDPI_demo executable
	
Usage of the OpenDPI_demo application:
	- the OpenDPI_demo application is invoked with a single option -f to which you must provide the path of a valid
	  pcap capture file
	- results will be written to standard output
