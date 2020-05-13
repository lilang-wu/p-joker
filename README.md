# p-joker -- iOS/MacOS Kernelcache/Extensions analysis tool
  ### For iOS kernelcache, this tool support 64bit kernelcache and have tested on iOS10/iOS11/iOS12/iOS13 kernelcache   
  ### For MacOS kernel extensions, it support all the extensions' mach-o file.  
  
# Usuage
## for p-joker.py (support iOS kernelcache analysis only, and -e feature can support iOS 12/13 now)
  Usage: python p-joker.py kernelcache -hkl [-K bundleID]

  ```
    Usage: python p-joker.py kernelcache -hkls [-Ke bundleID(or list)] [-d dir]
	 -h, --help
	 -k, --kext_list: list all the kext informations
	 -K, --kextdump kext_bundle_identifier: dump this kext
	 -d, --dir dumpdir: set the output dir
	 -l, --lzss: decrypted the kernelcache
	 -e, --extract: extract all meta classes and their methods for given extension bundleID  


 For example:
	 decrypt kernelcache, support bvx and complzss format:
		 $ python p-joker.py kernelcache.encrypted -l

	 list all the kexts info:
		 $ python p-joker.py kernelcache.decrypted -k

	 dump certain kext from kernelcache:
		 $ python p-joker.py kernelcache.decrypted -K com.apple.iokit.IOHIDFamily
		 $ python p-joker.py path/to/kernelcache -K all [-d dir]

	 extract all meta class and their functions information for all extensions within kernelcache:
		 $ python p-joker.py kernelcache.decrypted -e "['all']"

	 extract all meta class and their functions information for certain extensions within kernelcache:
		 $ python p-joker.py kernelcache.decrypted -e "['com.apple.iokit.IOHIDFamily']"

  ```

## for p-extension.py (support macOS only)
  ```
 Usage: python p-extensions.py -mpfc extension_path/extension_macho
	 -h, --help
	 -C, --classes: get all the metaclass for all extensions' macho file in the given extension_path
	 -c, --class: get all the metaclass for one extension macho
	 -m, --macho: only analyze one kernel extension macho
	 -M, --machoes: analyze all kernel extensions' macho file in the given extension_path
  ```
  
# Dependent libraries
  pyiokit  
  pylzfse  
  capstone=5.0.0 (https://github.com/aquynh/capstone/tree/next)  
  
  #### Note: please install the capstone in their next branch
  
# Support platforms
  MacOS/Windows/Linux
  
  
#
if you have any questions, just open the issue!
