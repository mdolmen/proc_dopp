# Process Doppelganging

My implementation of the process doppelganging injection technique presented at
the Black Hat 2017.

- https://www.blackhat.com/docs/eu-17/materials/eu-17-Liberman-Lost-In-Transaction-Process-Doppelganging.pdf
- https://www.youtube.com/watch?v=Cch8dvp836w

Got help from :
https://hshrzd.wordpress.com/2017/12/18/process-doppelganging-a-new-way-to-impersonate-a-process/ , especially for the undocumented functions definitions.

## Status

Partially working version on Windows 10 (1709) x64 : 

- Starts successfully a console application but failed to start a GUI one (need
  to modify the DLL path in the process parameters and maybe pass it an
  environment variables pointer).
- There is also an issue with the name in the process list which doesn't take
  the program name (_System idle process_ instead).
