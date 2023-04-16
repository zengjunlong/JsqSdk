How to use the scripts:

- netfilter2.inf is a fake inf file, required only for web service. It is not necessary to use it in your project. In this file replace the default name netfilter2 to your driver name. 

- netfilter2_x64.ddf and netfilter2_x86.ddf files are scripts for makecab tool from Microsoft SDK. In the scripts it is necessary to specify the correct path to inf file and the appropriate build of driver. Inf file is the same for both 32-bit and 64-bit driver builds. 

- sign.bat is a script for signing cab files. Replace the strings in script to required. 

- build_x64.bat and build_x86.bat call the scripts above to build and sign 64-bit and 32-bit cab files with appropriate inf and sys files. 

I.e. it is necessary to modify the files as specified above and call build_*.bat files. The generated cab files will be ready for signing via Microsoft service. 