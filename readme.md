# PatternScanner
## Description
PatternScanner is a project which enables runtime binary analysis. \
It allows you to: 
- Scan for arrays of bytes in a program with a mask (e.g: "\x3D\x4D\xE8\x00\x00\x00\x00\xC3", "xxx????x")
- Scan for cross-references to certain functions or strings in a program
- Scan using a custom routine, enabling you to have more control of how you are scanning without modifying the library.
- Find the prologue (start) and epilogue (end) of a function.
- Find all of the calls and jumps of a function 

What sets this pattern scanner apart from other pattern scanners is that it is multithreaded, which means that it can scan multiple pages at the same time. \
This design is ideal in most external applications, but when working internally (from within a program) it may not be ideal as creating a thread for every page is not exactly discrete. 
## Images
There are no images at the moment, but I will post some with benchmarks. Also, any benchmark binaries I use will be in the solution by default.

## How will I focus on performance?
I will be using both the AMD build and the Intel build to profile code using AMD uProf and Intel vTune.\
This will enable me to see which parts of the source are using the most CPU time, and I will try to find optimizations to lower scan times.\
The benches I will use have the following specs:

#### Bench 1 - AMD Build
CPU: AMD Ryzen 9 7900X\
RAM: 32GB CL36 DDR5 5600 MHz

#### Bench 2 - Intel Build
CPU: Intel Core i5 9300H\
RAM: 64GB CL22 DDR4 3200 MHz

The reason for using an Intel and AMD bench is to ensure that this project will run smoothly on different platforms and that the optimizations will be effective throughout.\
Also, I can use hardware-level profiling on both platforms to ensure that everything works properly.

## Do I plan to support this in the future?
Contributors are always welcome, and I like to make the process of contributing as straightforward as possible. \
To contribute, fork the project and then make your own pull request on this project comparing your fork to the current project. \
When contributing, add yourself to the bottom of the contributors section of the readme (if you are not already in it). \
If you discover a bug or issue in master, open an issue and I will do my best to fix it myself or assign a maintainer to fix it. You are also more than welcome to fix the issue and make a new PR. 

## Contributors
As more people help contribute to this project, this list will expand.\
[Fishy](https://github.com/Fish-Sticks) - General Consultation & Optimization \
[Expr](https://github.com/expressiongz) - Ease-of-use changes & General Consultation
