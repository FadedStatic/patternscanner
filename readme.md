# PatternScanner
## Description
PatternScanner is a project that is provided free of charge to any and all users.\
This scanner was designed to be blazingly fast, and to target x86_64 projects.\
x86 is not supported officially, but I will add macros which will compile different versions of the project dependent on build settings.

## Images
There are no images at the moment, but I will post some with benchmarks. Also, any benchmark binaries I use will be in the solution by default.

## How will I make it fast?
I will be using tools such as AMD uProf as well as Intel vTune (on different processors to test compatibility).\
This will enable me to see which parts of the source are using the most CPU time, and I will try to find optimizations to lower scan times.\
The benches I will use have the following specs:

#### Bench 1 - Desktop AMD Build
Motherboard: MSI MPG B650 Carbon Wifi\
CPU: AMD Ryzen 9 7900X\
GPU: Intel Arc A770 16GB LE\
RAM: 32GB CL36 Corsair Vengeance DDR5 5600 MHz

#### Bench 2 - Intel Laptop
Motherboard: Octavia CFS\
CPU: Intel Core i5 9300H\
GPU: Nvidia GeForce GTX 1650\
RAM: 64GB CL22 G.Skill DDR4 3200MHz

The reason for using an Intel and AMD bench is to ensure that this project will run smoothly on different platforms and that the optimizations will be effective throughout.\
Also, I can use hardware-level profiling on both platforms to ensure that everything works properly.

## Do I plan to support this in the future?
If people wish to contribute or provide comments on this project, I will gladly accept them.\
Simply create a new issue and I will get back to you within a week probably, or just message me on discord (if you have it).

## Credits
As more people help contribute to this project, this list will expand.
