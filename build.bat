@echo off

if /i "%1" equ "clean" (
	del *.pdb *.exe *.obj>nul
	exit /b
)

set compiler_flags=/nologo /W3 /Zi
set linker_flags=/incremental:no /opt:ref /opt:icf

call cl %compiler_flags% md5.c /link %linker_flags%
call cl %compiler_flags% sha1.c /link %linker_flags%
