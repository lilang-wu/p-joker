# p-joker -- iOS kernelcache kext dump tool which write in python
  ugly, this tool only support 64bit kernelcache and version >iOS10.0.0
  
# Usuage
  Usage: python p-joker.py kernelcache -hk [-K bundleID] "
  
    "-h, --help"
    
    "-k, --kext_list: list all the kext informations"
    
        example: python p-joker.py path/to/kernelcache -k
    "-K, --kextdump kext_bundle_identifier: dump this kext"
    
        example:
          1)dump all kexts:
            python p-joker.py path/to/kernelcache -K all [-d dir]
          2)dump one kexts:
            python p-joker.py path/to/kernelcache -K com.apple.security.sandbox [-d dir]
            
     "-d, --dir: output dir"
     
# Dependent libraries
  no

# Support platforms
  MacOS/Windows/Linux
# -----------------------------------------
if you have any issues, just let me know!
