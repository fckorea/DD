# DD
Detection-Dog
* https://github.com/fckorea/Detection-Dog

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
>   * -o &lt;Output file path&gt;, --output=&lt;Output file path&gt;: Set output file path.
>   * -t &lt;Output file type&gt;, --output_type=&lt;Output file type&gt;: Set output file type(csv, json, txt). default) csv
>   * --no-sub-dir: Set no traversal sub directory. default) Traversal
>   * -v, --verbose: Set verbose mode. default) False

## Make config
 * json style
 * required names
   * updated: string, ex) 2019-08-20
   * extension: array in string, ex) [ ".php", ".aspx" ]
   * pattern: array in object
     * pattern object
       * type: string, "string"|"regex"|"hex"|"yara"
       * data: string
         * string: "passthru"
         * regex: "^(test|pass)$"
         * hex: "0F 1F 3C"
         * yara: "rule test { strings: $string = \\"test\\" wide ascii $string2 = \\"pass\\" condition: $string or $string2 }"

## Build
### for Windows
* [pyinstaller --onefile dd.py] OR [build\build.bat]
### for Linux
* [pyinstaller --onefile dd.py] OR [build/build.sh]
