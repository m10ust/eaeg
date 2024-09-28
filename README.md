# eaeg
Enhanced Advanced Entropy Generator for Linux Kernels (This is the first kernel module I write so be gentle and you are welcome to improve it)

Enhanced Advanced Entropy Generator (EAEG) kernel module. This code indeed incorporates several advanced features and integrations that enhance its entropy generation capabilities. Here's a summary of the key improvements and features:

 1. Increased entropy pool size (32 elements) for better mixing.
 2. More tracked IRQs (256) for a wider range of entropy sources.
 3. Use of CPU microspikes (TSC - Time Stamp Counter) for additional randomness.
 4. Integration of hardware RNG (RDRAND instruction) when available.
 5. Improved mixing function using SHA-512 cryptographic hash.
 6. Network packet timing as an additional entropy source.
 7. More sophisticated entropy addition process, combining multiple sources.
 8. Flexible IRQ registration system.

This version offers a more comprehensive approach to entropy generation by leveraging multiple hardware and software sources. The use of cryptographic hashing (SHA-512) for mixing and the integration of hardware RNG are particularly noteworthy improvements to other entropy generators such haveg, Random Number Generators (RNG), Jitter Entropy RNG (Jent). I can integrate with your hardware rng (HRNG). If you have one it will use it to be part of its entropy generation without user's intervention. 

To compile and use this module from source:

Make sure you have "linux-headers" and "base-devel" installed:


Debian
```
sudo apt install linux-headers base-devel
```

Arch
```
sudo pacman -S linux-headers base-devel
```

Fedora & CentOS 7 and older
```
sudo dnf install linux-headers base-devel
```
or yum if you preffer...

openSUSE
```
sudo zypper install linux-headers base-devel
```

FreeBSD
```
sudo pkg install linux-headers base-devel
```

MacOS's brew
```
brew install linux-headers && brew install base-devel
```
(not sure about this one, proceed with care)


Save the code as eaeg.c (or download the file because I include both the sourcecode in a .txt file and the file.c ready to be compiled. You can also clone it precompiled and load it using "sudo insmod eaeg.ko" (not suggested))

Create a Makefile in the same directory with the content:

Create a file named "Makefile" and copy the following code in it. (The Makefile is included in the repo ready to be downloaded, I am only making those instructions for cautious people or people who wanna learn something while compiling this)
```
obj-m += eaeg.o
  
all:
 make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
  
clean:
  make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean ```
```
Compile the module:
```
make
```
Load the module:
```
sudo insmod eaeg.ko
```
Verify it's loaded:
```
Copylsmod | grep eaeg
```
Check kernel logs for any messages:
```
Copydmesg | tail
```
To unload:
```
Copysudo rmmod eaeg
```

Remember, this module interacts with low-level system components and should be thoroughly tested in a safe environment before any production use. Also, ensure you have the necessary kernel headers and build tools installed on your system.

GPL V3 author M4Y0U. You are free to use this software and improve it but I would appreciate if you used this GitHub so we can have version checks. 
