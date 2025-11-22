CFLAGS=/c /GS- /std:c++20
DEBUGCFLAGS=/Zi /MTd /D_DEBUG /EHsc /std:c++20

!IF "$(PROCESSOR_ARCHITECTURE)" != "x86" && "$(PROCESSOR_ARCHITECTURE)" != "AMD64"
!ERROR Only x86 and AMD64 architectures are supported or the PROCESSOR_ARCHITECTURE environment variable is not set.
!ELSEIF "$(PROCESSOR_ARCHITECTURE)" == "AMD64"
OUTDIR=..\bin\ 
IMDIR=x64\Release\ 
DOUTDIR=..\x64\Debug\ 
DIMDIR=x64\Debug\ 
OUTEXT=.x64.o
!ELSE
OUTDIR=..\bin\ 
IMDIR=Release\ 
DIMDIR=Debug\ 
DOUTDIR=..\Debug\ 
OUTEXT=.x86.o
!ENDIF

all: *.cpp
    @$(MAKE) $(patsubst %.c,%.obj, $(patsubst %.cpp, %.obj, $(patsubsti %, $(IMDIR)\%, $**)))
    @if not exist "$(OUTDIR)" mkdir "$(OUTDIR)"
    ren "$(IMDIR)*.obj" "*$(OUTEXT)"
    move /Y "$(IMDIR)\*.o" "$(OUTDIR)"

all-debug: *.cpp
    @$(MAKE) $(patsubst %.c,%.exe, $(patsubst %.cpp, %.exe, $(patsubsti %, $(DOUTDIR)\%, $**)))

.cpp{$(IMDIR)}.obj:
    @if not exist "$(IMDIR)" mkdir "$(IMDIR)"
    $(CPP) $(CFLAGS) /Fo"$@" $<

.cpp{$(DOUTDIR)}.exe:
    @if not exist "$(DIMDIR)" mkdir "$(DIMDIR)"
    @if not exist "$(DOUTDIR)" mkdir "$(DOUTDIR)"
    $(CPP) $(DEBUGCFLAGS) /Fo$(DIMDIR) /Fd$(DIMDIR) /Fe"$@" $< base/mock.cpp

clean:
     @if exist "$(DIMDIR)" rmdir /Q /S "$(DIMDIR)"
     @if exist "$(IMDIR)" rmdir /Q /S "$(IMDIR)"
     @if exist "$(OUTDIR)" rmdir /Q /S "$(OUTDIR)"
     @if exist "$(DOUTDIR)" rmdir /Q /S "$(DOUTDIR)"
