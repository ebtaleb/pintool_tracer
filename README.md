Experimenting with PinTool

If you have trouble running PinTools on Linux 4+ with GCC 5:
* Add to makefile.uni.config the flag"-fabi-version=2" to APP_CXXFLAGS_NOOPT and TOOL_CXXFLAGS_NOOPT
* Pass the parameter "-ifeellucky" to Pin when running the PinTool.
* Got the "fatal error: bits/c++config.h: No such file or directory" error? You need gcc's multilibs.
* Want a 32bit PinTool? Run `make TARGET=ia32`.
* Run `make help-run` for an idead of the command to be run.

Or just copy my makefile.uni.config file to the Pin Kit Config folder.
