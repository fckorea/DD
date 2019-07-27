#-*- coding: utf-8 -*-
#-------------------------------------------------------------------------------
# Name:		Detection Dog
# Purpose:
# Python version: 3.6
#
# Author:	fckorea
#
# Created:	2019-07-27
# (c) fckorea 2019
#-------------------------------------------------------------------------------

import sys
from optparse import OptionParser
import os.path
import logging
import logging.handlers
import json
import traceback
import re

LOGGER = None
LOG_FILENAME = './detection-dog.log'
CONFIG = {}

#=============================== Main Functions ===============================#

#=============================== Config & Init Function ===============================#
def fnGetConfig(argOptions):
	global CONFIG

	try:
		if os.path.isfile(argOptions.o_sConfig):
			CONFIG = json.loads(open(argOptions.o_sConfig, encoding='UTF8').read())
			LOGGER.info(' Read data')
			LOGGER.info(' Updated: %s, Count of data: %d, Target extension: %s ' % (CONFIG['updated'], len(CONFIG['pattern']), ', '.join(CONFIG['extension'])))
			return True
		else:
			LOGGER.error(' * Config file not found.')
	except:
		LOGGER.debug(' *** Error read config file.')
		LOGGER.debug(traceback.format_exc())
	
	return False

#=============================== Main Functions ===============================#
def fnMain(argOptions, argArgs):
	global LOGGER
	global CONFIG

	try:
		LOGGER.debug('in fnMain')
	except:
		raise

#=============================== OptionParser Functions ===============================#
def fnSetOptions():
	l_hParser = None

	l_lOptions = [
		{ 'Param': ('-c', '--config'), 'action': 'store', 'metavar': '<Config file path>', 'type': 'string', 'dest': 'o_sConfig', 'default': 'config.conf', 'help': 'Set config file path.\t\tdefault) config.conf (contents type is JSON)' },
		{ 'Param': ('-t', '--target'), 'action': 'store', 'metavar': '<Detection target path>', 'type': 'string', 'dest': 'o_sTarget', 'help': 'Set target path.\t\t*Required' },
		{ 'Param': ('-s', '--sub_dir'), 'action': 'store_false', 'metavar': '<Is sub directory>', 'dest': 'o_bSubDir', 'help': 'Set travel sub directory.\tdefault) False' },
		{ 'Param': ('-v', '--verbose'), 'action': 'store_false', 'metavar': '<Verbose Mode>', 'dest': 'o_bVerbose', 'help': 'Set verbose mode.\t\tdefault) False' }
	]
	l_sUsage = '%prog [options]\n ex) %prog ...'

	l_hParser = OptionParser(usage = l_sUsage, version = '%prog 0.1')

	for l_dOption in l_lOptions:
		l_tParam = l_dOption['Param']
		del l_dOption['Param']
		l_hParser.add_option(*l_tParam, **l_dOption)

	return l_hParser

def fnGetOptions(argParser):
	if(len(sys.argv) == 1):
		return argParser.parse_args(['--help'])

	return argParser.parse_args()

def fnInit():
	global LOGGER
	global LOG_FILENAME

	LOGGER = logging.getLogger('Detection-Dog')
	LOGGER.setLevel(logging.DEBUG)

	formatter = logging.Formatter('[%(levelname)s] - %(filename)s:%(lineno)s\t- %(asctime)s - %(message)s')
	
	file_handler = logging.handlers.TimedRotatingFileHandler(LOG_FILENAME, atTime='midnight', backupCount=7, encoding='UTF-8')
	file_handler.suffix = '%Y%m%d'
	file_handler.setFormatter(formatter)

	stream_handler = logging.StreamHandler()
	stream_handler.setFormatter(formatter)

	LOGGER.addHandler(file_handler)
	LOGGER.addHandler(stream_handler)

	return True

if __name__ == '__main__':
	if fnInit():
		LOGGER.info('Start Detection Dog...')

		l_hParser = fnSetOptions()
		(l_hOptions, l_vArgs) = fnGetOptions(l_hParser)
		if fnGetConfig(l_hOptions):
			fnMain(l_hOptions, l_vArgs)

		LOGGER.info('Terminate Detection Dog...')
