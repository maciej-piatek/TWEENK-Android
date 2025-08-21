# TWEENK-Android
Tweenk is an encrypted note taking app written in Golang. It uses Fyne as its GUI environment. Its a lightweight application made to run on everything that Go and Fyne can run on.
I'm planning to update it frequently and add new useful stuff to it so it will become a powerhouse of a note app in the future.
It uses a custom .tweenk extension and AES-256 CBC encryption.
### This is an android redesigned version, it only changes layout so it looks better on a phone screen.

## Current features of TWEENK Android:
* Dark/Light mode switch (it saves its settings in an .ini file)
* Text hiding privacy view switch
* Strong AES-256 CBC encryption
* Ease of use
* Safety (Constantly updating Go and Fyne to the newest versions to avoid bugs and exploits)

## **About contributing**

1. Feel free to fork the repository if you want to add something new yourself
2. Create a feature branch: `git checkout -b feature-new`
3. Commit changes: `git commit -m "Added feature"`
4. Push to your branch: `git push origin feature-new`
5. Submit a pull request.

## **Stay Connected**
Star the repository if you find it useful or think its cool!  
For support, use [GitHub Issues](https://github.com/maciej-piatek/TWEENK-Android/issues) or contact me via email mpdev@memeware.net.

# How to install from source:
go install fyne.io/fyne/v2/cmd/fyne@latest

fyne get github.com/maciej-piatek/TWEENK-Android

You need to have android SDK and NDK installed and set up to compile it.

# THIS IS STILL A WORK IN PROGRESS, A LOT OF STUFF HAS TO BE CHANGED FOR IT TO BE COMFORTABLE TO USE ON A TOUCHSCREEN
