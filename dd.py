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
import datetime
import time
import json
import csv
import traceback
import re

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

#=============================== Check Functions ===============================#
def fnProcess(argTarget, argSubDir):
    global LOGGER
    global CONFIG
    global RESULT

    try:
        target_list = fnGetTargetList(argTarget, argSubDir)
        RESULT['summary']['target_count'] = RESULT['summary']['target_count'] + len(target_list) if 'target_count' in RESULT['summary'] else len(target_list)
        
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
                        'check_result': result
                    })
                    for res in result:
                        if res['line'] == 0:
                            LOGGER.info(' + %s(%s):binary, %d' % (check_path, res['data'], res['column']))
                        else:
                            LOGGER.info(' + %s(%s):%d, %d' % (check_path, res['data'], res['line'], res['column']))

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

    try:
        read_file = open(argCheckFilePath, encoding='UTF8')
        content = read_file.read()
        LOGGER.debug(' * Read UTF-8.')
    except:
        read_file.close()
        read_file = open(argCheckFilePath, 'rb')
        content = read_file.read()
        LOGGER.debug(' * Cannot read UTF-8, re-read binary.')

    if len(content) > 0:
        for pattern in CONFIG['pattern']:
            idx = fnCheckPattern(content, pattern['type'], pattern['data'])
            if idx > -1:
                (line_at, column_at) = fnGetFindAt(content, idx)
                if line_at == 0:
                    LOGGER.debug(' * Matched pattern!!! (%s) - %s:binary, %d' % (pattern['data'], argCheckFilePath, column_at))
                else:
                    LOGGER.debug(' * Matched pattern!!! (%s) - %s:%d, %d' % (pattern['data'], argCheckFilePath, line_at, column_at))
                result.append({
                    'type': pattern['type'],
                    'data': pattern['data'],
                    'line': line_at,
                    'column': column_at
                })
    else:
        LOGGER.debug(' * No content SKIP!!!')

    read_file.close()

    return result

def fnCheckPattern(argContent, argCheckType, argCheckValue):
    global LOGGER

    if argCheckType == 'string':
        LOGGER.debug(' * Check string type(%s), value(%s)' % (argCheckType, argCheckValue))

        if type(argContent) is bytes:
            LOGGER.debug(' * Check content is bytes.')
            return argContent.find(argCheckValue.encode())
        return argContent.find(argCheckValue)
    elif argCheckType == 'regex':
        LOGGER.debug(' * Check regex type(%s), value(%s)' % (argCheckType, argCheckValue))

        if argCheckValue[0] == '/' and argCheckValue[-1] == '/':
            argCheckValue = argCheckValue[1:-1]
        regex = re.compile(argCheckValue, re.MULTILINE | re.IGNORECASE)
        matched = regex.search(argContent)

        if matched is None:
            return -1
        else:
            return matched.span()[0]

def fnGetFindAt(argContent, argIdx):
    column_count = argIdx
    line_count = argContent[:argIdx].count('\n') + 1 if type(argContent) is not bytes else 0

    if type(argContent) is bytes:
        return (line_count, (column_count + 1))
        
    if line_count > 0:
        before_lines = argContent[:argIdx].split('\n')[:-1]
        column_count -= len('\n'.join(before_lines))
        if argContent[:argIdx].count('\r') > 0:
            column_count -= len(before_lines)
        
        if line_count == 1:
            column_count += 1
    
    return (line_count, column_count)

#=============================== Output Function ===============================#
def fnOutputCSV(argOutputPath):
    global RESULT

    with open(argOutputPath, 'w', newline='') as csv_file:
        csv_writer = csv.writer(csv_file, delimiter='\t', quotechar='|', quoting=csv.QUOTE_MINIMAL)
        
        csv_writer.writerow([ 'Exec:', RESULT['exec'] ])
        csv_writer.writerow([ 'Check extension:', RESULT['check_extension'] ])
        csv_writer.writerow([ 'Check file count:', RESULT['summary']['target_count']])
        csv_writer.writerow([])
        csv_writer.writerow([ 'Path', 'Line, Column', 'Match' ])

        for res in RESULT['result']:
            for check_res in res['check_result']:
                csv_writer.writerow([ res['path'], ('%d, %d' % (check_res['line'], check_res['column'])), check_res['data'] ])
    
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

    with open(argOutputPath, 'w') as txt_file:
        txt_file.write('Exec: %s\n' % (RESULT['exec']))
        txt_file.write('Check extension: %s\n' % (RESULT['check_extension']))
        txt_file.write('Check file count: %d\n' % (RESULT['summary']['target_count']))
        txt_file.write('\n')

        file_idx = 1

        for res in RESULT['result']:
            txt_file.write('%d. %s (Matched: %d)\n' % (file_idx, res['path'], len(res['check_result'])))
            check_idx = 1
            for check_res in res['check_result']:
                txt_file.write('\t+ %d. %s - %d, %d\t(pattern: %s)\n' % (check_idx, res['path'], check_res['line'], check_res['column'], check_res['data']))
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
        { 'Param': ('-t', '--output_type'), 'action': 'store', 'metavar': '<Output file type>', 'type': 'string', 'dest': 'o_sOutputType', 'default': 'csv', 'help': 'Set output file type(json, csv, txt).\t\tdefault) csv' },
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
