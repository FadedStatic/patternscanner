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

## How to Contribute
Contributors are always welcome, and I like to make the process of contributing as straightforward as possible. \
To contribute, fork the project and then make your own pull request on this project comparing your fork to the current project. \
When contributing, add yourself to the bottom of the contributors section of the readme (if you are not already in it). \
If you discover a bug or issue in master, open an issue and I will do my best to fix it myself or assign a maintainer to fix it. You are also more than welcome to fix the issue and make a new PR. 

## Contributors
As more people help contribute to this project, this list will expand.\
[Fishy](https://github.com/Fish-Sticks) - General Consultation & Optimization \
[Expr](https://github.com/expressiongz) - Ease-of-use changes & General Consultation
