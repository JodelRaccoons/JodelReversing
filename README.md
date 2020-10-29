# JodelReversing
Some details about reversing the Jodel-App

This repository consists of different parts. 

#### Jodel-Keyhack-Frida
For one part there are three different methods to extract the HMAC-Key from the Jodel APK. 
The most reliable method as of my tests is the [JodelKeyhack-Frida](https://github.com/JodelRaccoons/JodelReversing/tree/master/Jodel-Keyhack-Frida) but it requires a rooted Android Device with SELinux set to permissive and [frida-server](https://github.com/frida/frida/releases) installed.

#### Jodel-Keyhack-v2
If Jodel-Keyhack-Frida is not an option for you, you could try the Jodel-Keyhack-v2 which is based on IDA Pro and their Python scripting interface. 
From time to time it is a little bit unstable but generally it produces working and valid results.

#### Jodel-Keyhack-v3
The last option is to use the Jodel-Keyhack-v3 which is based on radare2 and includes a fancy webinterface for uploading the APK and displaying the signature. 
The v3 is currently not working as radare2 is not able to resolve the function names correctly. A quick and dirty hack would be searching for the correct pattern inside the functions. 
Althogh this is a possibility, it did not prove to be reliable. Therefore the v3 is as of now **BROKEN**.

### Information about reversing
The markdown documents included in this repository sums up basics about the application and steps to reverse engenieer it.
There might be some caveats and none of the things documented are guaranteed to work anymore. 
The algorithms used could change at any point in time.

In case some things do not work anymore or parts of the documentation are not understandable, feel free to create an issue on this repository.
