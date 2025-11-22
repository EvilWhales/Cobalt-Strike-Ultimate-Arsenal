#!/usr/bin/env bash

# make our output look nice...
kit_name="Process Inject kit"

function print_good () {
   echo -e "[${kit_name}] \x1B[01;32m[+]\x1B[0m $1"
}

function print_error () {
   echo -e "[${kit_name}] \x1B[01;31m[-]\x1B[0m $1"
}

function print_info () {
   echo -e "[${kit_name}] \x1B[01;34m[*]\x1B[0m $1"
}

#
# Compile the 64-bit version of the object files
#
function compile_x64() {
        print_info "Compile ${1}.x64.o"
        ${CCx64}-gcc -m64 $options -c src/${1}.c -o "${2}/${1}.x64.o"
}

#
# Compile the 32-bit version of the object files
#
function compile_x86() {
        print_info "Compile ${1}.x86.o"
        ${CCx86}-gcc $options -c src/${1}.c -o "${2}/${1}.x86.o"
}


# compiler flags to pass to all builds. Use this to set optimization level or tweak other fun things.
export options="-Os -masm=intel"

# change up the compiler if you need to
export CCx86="i686-w64-mingw32"
export CCx64="x86_64-w64-mingw32"

# check for a cross-compiler
if [ $(command -v ${CCx64}-gcc) ]; then
        print_good "You have a x86_64 mingw--I will recompile the process inject beacon object files"
else
        print_error "No cross-compiler detected. Try: apt-get install mingw-w64"
        exit 2
fi


#
# compile the process inject object files
#

if [[ $# -ne 1 ]]; then
    print_error "Missing parameters"
    print_error "Provide a DIST directory to save the output"
    print_error "Example:"
    print_error '  ./build.sh /tmp/dist/process_inject'

    exit 2
fi

# Clean

dist_directory="${1}"

rm -rf "${dist_directory}"
mkdir -p "${dist_directory}"

compile_x64 process_inject_spawn "${dist_directory}"
compile_x86 process_inject_spawn "${dist_directory}"

compile_x64 process_inject_explicit "${dist_directory}"
compile_x86 process_inject_explicit "${dist_directory}"

sed 's/KITNAME/process_inject_kit/' ../../templates/helper_functions.template > "${dist_directory}/processinject.cna"
cat ./script_template.cna >> "${dist_directory}/processinject.cna"

print_good "The Process inject object files are saved in '${dist_directory}'"