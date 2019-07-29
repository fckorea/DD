# Detection-Dog
https://github.com/fckorea/Detection-Dog

## Description
### This python script find files using string or regular expression.

## Environment
> * Python3.7
> * pyinstaller [Optional for build]

## Usages
> python3 dd.py [options] file or directory list...
> * python3 dd.py /var/www/data /var/www/upload
> * python3 dd.py -v /var/www/data /var/www/upload
> * Options
>   * --version: show program's version number and exit
>   * -h, --help: show this help message and exit
>   * -c &lt;Config file path&gt;, --config=&lt;Config file path&gt;: Set config file path. default: config.conf)
>   * --no-sub-dir: Set no traversal sub directory. default) Traversal
>   * -v, --verbose: Set verbose mode. default) False

## Build
### for Windows
* [pyinstaller --onefile dd.py] OR [build\build.bat]
### for Linux
* [pyinstaller --onefile dd.py] OR [build/build.sh]