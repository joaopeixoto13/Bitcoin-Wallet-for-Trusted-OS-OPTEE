# Trusted-Application-and-Client-Application-of-Bitcoin-Wallet-to-OPTEE-Rust

In this project, the objective is to carry out the portability of a **Bitcoin Wallet Trusted Application and
Corresponding client application for Trusted OS OPTEE**. A Client Application is
responsible for interacting with a trusted application, which performs operations
safely within the protected environment of the TEE. Traditionally how trusted applications are
written in low-level languages (i.e., C), which results in many Trusted Applications
there were times. These comparative applications can be used to compromise a
system as a whole. The use of the Rust programming language allows a reduction
of the vulnerabilities of this type of application, due to their security features.
Noteworthy is its comparable performance to C, as well as its growing popularity in
domains including system programming, making it an ideal choice for
implementation of critical applications. Should be noted the challenge of porting the applications to the
new language, maintaining security and efficiency, in addition to becoming familiar with the
Armv8-A architecture and **Arm TrustZone technology used in virtually all Android phones**. The student will use open-source project tools, such as qemu and
gdb. In the end, the student must have carried out the study of the support for TEEs of architecture
Armv8-A and have implemented a reliable client application in **Rust**, so that these
run on a complete system that includes the Linux operating system, ensuring a
system safety and efficiency.
