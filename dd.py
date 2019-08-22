#-*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:        Detection Dog
# Purpose:
# Python version: 3.7.3
#
# Author:    fckorea
#
# Created:    2019-07-27
# (c) fckorea 2019
#-------------------------------------------------------------------------------

import sys
from optparse import OptionParser
import os.path
import logging
import logging.handlers
import string
import datetime
import time
import json
import csv
import traceback
import re
import yara

PROG_VER = '0.1'
LOGGER = None
LOG_FILENAME = './detection-dog.log'
CONFIG = {}
RESULT = {
    'exec': '',
    'check_extension': '',
    'summary': {},
    'result': []
}
READ_REASON_LEN = 5
YARA_RES_IN_CALLBACK = {}

#=============================== Check Functions ===============================#
def fnProcess(argTarget, argSubDir):
    global LOGGER
    global CONFIG
    global RESULT

    try:
        target_list = fnGetTargetList(argTarget, argSubDir)
        RESULT['summary']['target_count'] = RESULT['summary']['target_count'] + len(target_list) if 'target_count' in RESULT['summary'] else len(target_list)
        RESULT['summary']['result_count'] = 0
        
        for check_path in target_list:
            LOGGER.info('Check file("%s")' % (check_path))

            check_path_ext = os.path.splitext(check_path)[-1].lower()

            if check_path_ext in CONFIG['extension']:
                LOGGER.debug(' * Matched extension("%s")' % (check_path_ext))

                result = fnCheckFile(check_path)

                LOGGER.info('Check result (%s) - Find: %d' % (check_path, len(result)))

                if len(result) > 0:
                    RESULT['result'].append({
                        'path': check_path,
                        'result_count': len(result),
                        'check_result': result
                    })

                    RESULT['summary']['result_count'] += len(result)

                    for res in result:
                        LOGGER.debug(' * Raw result(%s)' % (res))
                        if res['line'] == 0:
                            LOGGER.info(' + %s:binary, %d (%s pattern: %s, %s)' % (check_path, res['column'], res['reason'], res['matched'][1], res['matched'][2]))
                        else:
                            LOGGER.info(' + %s:%d, %d (%s pattern: %s, %s)' % (check_path, res['line'], res['column'], res['reason'], res['matched'][1], res['matched'][2]))

    except:
        LOGGER.error(' *** Error in processing.')
        LOGGER.debug(traceback.format_exc())

def fnGetTargetList(argTarget, argSubDir):
    target_list = []

    if os.path.isfile(argTarget):
        target_list.append(os.path.abspath(argTarget))
    elif os.path.isdir(argTarget):
        for (path, dir, files) in os.walk(argTarget):
            for filename in files:
                target_list.append(os.path.abspath(os.path.join(path, filename)))
            if argSubDir is None or argSubDir is False:
                break
    
    return target_list

def fnCheckFile(argCheckFilePath):
    result = []
    
    for pattern in CONFIG['pattern']:
        matchInfo = fnCheckPattern(argCheckFilePath, pattern['type'].lower(), pattern['data'])
        if matchInfo != -1 and len(matchInfo) > 0:
            for match in matchInfo:
                match = (match[0], match[1], ''.join([ chr(x) if chr(x) in string.printable else '\\x%02x' % x for x in match[2] ]))
                (line_at, column_at) = fnGetFindAt(argCheckFilePath, match[0])
                if line_at == 0:
                    LOGGER.debug(' * Matched pattern!!! (%s) - %s:binary, %d' % (pattern['data'], argCheckFilePath, column_at))
                else:
                    LOGGER.debug(' * Matched pattern!!! (%s) - %s:%d, %d' % (pattern['data'], argCheckFilePath, line_at, column_at))
                result.append({
                    'type': pattern['type'],
                    'pattern': pattern['data'],
                    'matched': match,
                    'reason': fnGetMatchData(argCheckFilePath, match),
                    'line': line_at,
                    'column': column_at
                })

    return result

def yaraCallback(argData):
    global YARA_RES_IN_CALLBACK

    LOGGER.debug(' * Yara rule result.\t%s', argData)
    YARA_RES_IN_CALLBACK = argData
    yara.CALLBACK_CONTINUE

def fnCheckPattern(argCheckFilePath, argCheckType, argCheckValue):
    global LOGGER

    LOGGER.debug(' * Check content type(%s), value(%s)' % (argCheckType, argCheckValue))

    if argCheckType == 'string':
        # Escape
        argCheckValue = argCheckValue.replace('"', '\\"')

        yara_string = 'rule str { strings: $str = \"%s\" condition: $str }' % argCheckValue
        LOGGER.debug(' * Convert string to yara rule.\t%s' % (yara_string))
    elif argCheckType == 'regex':
        if argCheckValue[0] == '/' and argCheckValue[-1] == '/':
            argCheckValue = argCheckValue[1:-1]

        yara_string = 'rule regex { strings: $regex = /%s/ condition: $regex }' % argCheckValue
        LOGGER.debug(' * Convert regex to yara rule.\t%s' % (yara_string))
    elif argCheckType == 'hex':
        yara_string = 'rule hex { strings: $hex = { %s } condition: $hex }' % argCheckValue
        LOGGER.debug(' * Convert hex to yara rule.\t%s' % (yara_string))
    elif argCheckType == 'yara':
        yara_string = argCheckValue

    try:
        rules = yara.compile(source=yara_string)

        matches = rules.match(argCheckFilePath, callback=yaraCallback)
    except:
        # LOGGER.error(' *** Error execute yara path.')
        # LOGGER.debug(traceback.format_exc())

        try:
            content = fnReadFile(argCheckFilePath)
            matches = rules.match(data=content, callback=yaraCallback)
        except:
            LOGGER.error(' *** Error execute yara data.')
            LOGGER.debug(traceback.format_exc())
    
    if len(matches):
        return YARA_RES_IN_CALLBACK['strings']
    return []

def fnGetFindAt(argCheckFilePath, argMatchAt):
    column_count = argMatchAt

    content = fnReadFile(argCheckFilePath)

    line_count = content[:argMatchAt].count('\n') + 1 if type(content) is not bytes else 0

    if type(content) is bytes:
        LOGGER.debug(' * Content is bytes.')
        return (line_count, (column_count + 1))
    
    if line_count > 0:
        before_lines = content[:argMatchAt].split('\n')[:-1]
        column_count -= len('\n'.join(before_lines))
        
        if line_count == 1:
            column_count += 1
    
    return (line_count, column_count)

def fnGetMatchData(argCheckFilePath, argMatch):
    global READ_REASON_LEN

    content = fnReadFile(argCheckFilePath)

    return ''.join([ chr(x) if chr(x) in string.printable else '\\x%02x' % x for x in content[(0 if (argMatch[0] - READ_REASON_LEN) < 0 else (argMatch[0] - READ_REASON_LEN)):(None if (argMatch[0] + len(argMatch[2]) + READ_REASON_LEN) > len(content) else (argMatch[0] + len(argMatch[2]) + READ_REASON_LEN))] ]).replace('\n', '\\n').replace('\r', '\\r')

def fnReadFile(argCheckFilePath):
    content = ''

    try:
        read_file = open(argCheckFilePath, newline='', encoding='UTF8')
        content = read_file.read()
        LOGGER.debug(' * Read UTF-8.')
    except:
        read_file.close()
        read_file = open(argCheckFilePath, 'rb')
        content = read_file.read()
        LOGGER.debug(' * Cannot read UTF-8, re-read binary.')
    finally:
        read_file.close()
    
    return content

#=============================== Output Function ===============================#
def fnOutputCSV(argOutputPath):
    global RESULT

    with open(argOutputPath, 'w', newline='', encoding='UTF-8') as csv_file:
        csv_writer = csv.writer(csv_file, delimiter='\t', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        
        csv_writer.writerow([ 'Exec:', RESULT['exec'] ])
        csv_writer.writerow([ 'Check extension:', RESULT['check_extension'] ])
        csv_writer.writerow([ 'Check file count:', RESULT['summary']['target_count']])
        csv_writer.writerow([ 'Total result count:', RESULT['summary']['result_count']])
        csv_writer.writerow([])
        csv_writer.writerow([ 'Path', 'Line, Column', 'Match', 'PatternType', 'Pattern' ])

        for res in RESULT['result']:
            for check_res in res['check_result']:
                if check_res['line'] == 0:
                    csv_writer.writerow([ res['path'], ('binary, %d' % (check_res['column'])), check_res['reason'], check_res['matched'][1], check_res['matched'][2] ])
                else:
                    csv_writer.writerow([ res['path'], ('%d, %d' % (check_res['line'], check_res['column'])), check_res['reason'], check_res['matched'][1], check_res['matched'][2] ])
    
    csv_file.close()
    return True

def fnOutputJSON(argOutputPath):
    global RESULT

    with open(argOutputPath, 'w') as json_file:
        json.dump(RESULT, json_file, indent=4)
    
    json_file.close()
    return True

def fnOutputTxt(argOutputPath):
    global RESULT

    with open(argOutputPath, 'w', encoding='UTF-8') as txt_file:
        txt_file.write('Exec: %s\n' % (RESULT['exec']))
        txt_file.write('Check extension: %s\n' % (RESULT['check_extension']))
        txt_file.write('Check file count: %d\n' % (RESULT['summary']['target_count']))
        txt_file.write('Total result count: %d\n' % (RESULT['summary']['result_count']))
        txt_file.write('\n')

        file_idx = 1

        for res in RESULT['result']:
            txt_file.write('%d. %s (Matched: %d)\n' % (file_idx, res['path'], len(res['check_result'])))
            check_idx = 1
            for check_res in res['check_result']:
                if check_res['line'] == 0:
                    txt_file.write('\t+ %d. %s:binary, %d\t(pattern: %s, %s)\n' % (check_idx, check_res['reason'], check_res['column'], check_res['matched'][1], check_res['matched'][2]))
                else:
                    txt_file.write('\t+ %d. %s:%d, %d\t(pattern: %s, %s)\n' % (check_idx, check_res['reason'], check_res['line'], check_res['column'], check_res['matched'][1], check_res['matched'][2]))
                check_idx += 1
            file_idx += 1
    return True

#=============================== Config & Init Function ===============================#
def fnGetConfig(argConfigFilePath):
    global LOGGER
    global CONFIG

    try:
        if os.path.isfile(argConfigFilePath):
            CONFIG = json.loads(open(argConfigFilePath, encoding='UTF8').read())
            CONFIG['extension'] = [ item.lower() if item.startswith('.') else '.' + item.lower() for item in CONFIG['extension'] ]
            LOGGER.debug(' * Read config data')
            LOGGER.debug(' * Updated: %s, Count of data: %d, Target extension: %s ' % (CONFIG['updated'], len(CONFIG['pattern']), ', '.join(CONFIG['extension'])))
            return True
        else:
            LOGGER.error(' * Config file not found.')
    except:
        LOGGER.error(' *** Error read config file.')
        LOGGER.debug(traceback.format_exc())
    
    return False

#=============================== Main Functions ===============================#
def fnMain(argOptions, argArgs):
    global LOGGER
    global CONFIG

    RESULT['exec'] = ' '.join(sys.argv)
    RESULT['check_extension'] = ', '.join(CONFIG['extension'])

    try:
        for target in argArgs:
            target = os.path.abspath(target)

            LOGGER.info('Check target "%s"...' % (target))
            if os.path.isfile(target) or os.path.isdir(target):
                LOGGER.info('Target("%s") is %s.' % (target, 'file' if os.path.isfile(target) else ('directory (sub: %s)' % argOptions.o_bSubDir)))
                fnProcess(target, argOptions.o_bSubDir)
            else:
                LOGGER.info('Target("%s") is not found.' % (target))

        if argOptions.o_sOutputFilePath:
            output_path = os.path.abspath(argOptions.o_sOutputFilePath)

            if argOptions.o_sOutputType == 'csv':
                fnOutputCSV(output_path)
            elif argOptions.o_sOutputType == 'json':
                fnOutputJSON(output_path)
            elif argOptions.o_sOutputType == 'txt':
                fnOutputTxt(output_path)
    except:
        raise

#=============================== OptionParser Functions ===============================#
def fnSetOptions():
    global PROG_VER

    parser = None

    options = [
        { 'Param': ('-c', '--config'), 'action': 'store', 'metavar': '<Config file path>', 'type': 'string', 'dest': 'o_sConfigFilePath', 'default': 'config.conf', 'help': 'Set config file path.\t\tdefault) config.conf (contents type is JSON)' },
        { 'Param': ('-o', '--output'), 'action': 'store', 'metavar': '<Output file path>', 'type': 'string', 'dest': 'o_sOutputFilePath', 'help': 'Set output file path.' },
        { 'Param': ('-t', '--output_type'), 'action': 'store', 'metavar': '<Output file type>', 'type': 'string', 'dest': 'o_sOutputType', 'default': 'csv', 'help': 'Set output file type(csv, json, txt).\t\tdefault) csv' },
        { 'Param': ('', '--no-sub-dir'), 'action': 'store_false', 'metavar': '<No traversal sub directory>', 'dest': 'o_bSubDir', 'default': True, 'help': 'Set no traversal sub directory.\tdefault) Treversal' },
        { 'Param': ('-v', '--verbose'), 'action': 'store_true', 'metavar': '<Verbose Mode>', 'dest': 'o_bVerbose', 'default': False, 'help': 'Set verbose mode.\t\tdefault) False' }
    ]
    usage = '%prog [options] <File or Dir path>\n\tex) %prog test\\ test.php\n\tex) %prog -v test.php\n\tex) %prog --no-sub-dir test\\'

    parser = OptionParser(usage = usage, version = '%prog ' + PROG_VER)

    for option in options:
        param = option['Param']
        del option['Param']
        parser.add_option(*param, **option)

    return parser

def fnGetOptions(argParser):
    if len(sys.argv) == 1:
        return argParser.parse_args(['--help'])

    if len(argParser.parse_args()[1]) == 0:
        return argParser.parse_args(['--help'])

    return argParser.parse_args()

def fnInit(argOptions):
    global LOGGER
    global LOG_FILENAME

    LOGGER = logging.getLogger('Detection-Dog')

    if argOptions.o_bVerbose is True:
        LOGGER.setLevel(logging.DEBUG)
    else:
        LOGGER.setLevel(logging.INFO)

    formatter = logging.Formatter('[%(levelname)s] - %(filename)s:%(lineno)s\t- %(asctime)s - %(message)s')
    
    file_handler = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME, when='midnight', backupCount=7, encoding='UTF-8')
    file_handler.suffix = '%Y%m%d'
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    LOGGER.addHandler(file_handler)
    LOGGER.addHandler(stream_handler)

    return True

if __name__ == '__main__':
    parser = fnSetOptions()
    (parsed_options, argvs) = fnGetOptions(parser)
    if fnInit(parsed_options):
        LOGGER.info('Start Detection Dog...')
        if fnGetConfig(parsed_options.o_sConfigFilePath):
            LOGGER.info('Config file("%s")' % (parsed_options.o_sConfigFilePath))
            LOGGER.info('Updated: %s, Count of data: %d, Target extension: %s ' % (CONFIG['updated'], len(CONFIG['pattern']), ', '.join(CONFIG['extension'])))
            fnMain(parsed_options, argvs)
        LOGGER.info('Terminate Detection Dog...')
