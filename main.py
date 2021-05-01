# # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Telegram media-downloader							#
# # # # # # # # # # # # # # # # # # # # # # # # # # #  

from argparse import ArgumentParser
from configparser import ConfigParser
from loguru import logger
from telethon.sync import TelegramClient
from telethon.errors.rpcerrorlist import FileReferenceExpiredError
from tqdm import tqdm

import os

from virustotalClient import Virustotal_API
from clam_scanner import Clam_scanner

# Class to display download progressbar
# Atm. bitrates are buggy, resulting in displayed speeds of 2-3Pb/s
# Therefore is not used
class DownloadProgressBar(tqdm):
    def update_to(self, b=1, bsize=1, tsize=None):
        if tsize is not None:
            self.total = tsize
        self.update(b * bsize - self.n)


class Telegram_client(TelegramClient):
	def __init__(self, name, api_id, api_hash):
		super().__init__(name, api_id, api_hash)
		self.start()

	def consume_files(self, channel):
		logger.info("Checking all messages for files")
		ch_entity = self.get_entity(channel)
		messages = self.iter_messages(ch_entity)

		for msg in messages:
			logger.info("Consuming new message")
			if hasattr(msg, "media"):
				logger.info(f"Found file in message {msg.id}")
				filename = self._download(msg)
				if filename:
					result = self.eval_file(filename)	
				
	def _download(self, msg):
		logger.info("Downloading file")

		try:
			result = self.download_media(msg.media, DOWNLOAD_DEST)
			logger.success(f"File saved to {result}")

		except FileReferenceExpiredError as e:
			result = None
			logger.error("An exception occured while downloading file:", e)

		return result

	def eval_file(self, filename):
		# check virustotal API
		vt = Virustotal_API(VT_API_KEY)
		result = vt.is_safe(filename)

		# File not known by Virustotal to be malicious or suspicious
		# Evaluated to be safe
		if result == 1:
			logger.success(f"File {filename} has been evaluated as safe")

		# File known by Virustotal to be malicious
		elif result == 0:
			os.remove(filename)
			logger.warning(f"File {filename} concluded as malicious and removed")

		# File either not know by Virustotal or has been reported suspicious but not malicious.
		elif result == 2:
			# Check file with ClamAV
			scanner = Clam_scanner()
			num_infected_files, num_scanned_files = scanner.clam_eval(filename)

			if num_scanned_files < 1:
				logger.info(f"Unable to scan {filename}")
				scanner.rename_unscanned(filename)
			
			elif num_infected_files == 0:
				logger.success(f"File {filename} concluded as safe by ClamAV")
			
			else:
				os.remove(filename)
				logger.warning(f"File {filename} concluded as malicious by ClamAV and removed")



if __name__ == "__main__":
	logger.info("Starting program")
	argparser = ArgumentParser()

	arguments = {
		("-channel", "store", str, "String representing channel to download media from"),
		("-destination", "store", str, "Path to directory where downloads will be saved")
	}

	for key, action, type, help in arguments:
		argparser.add_argument(key, action=action, type=type, help=help)

	args = argparser.parse_args()
	cfg = ConfigParser()
	cfg.read("config.cfg")

	API_ID = cfg["Telegram"]["id"]
	API_HASH = cfg["Telegram"]["hash"]
	VT_API_KEY = cfg["Virustotal"]["api_key"]
	CHANNEL = args.channel if args.channel else cfg["Telegram"]["channel"]
	DOWNLOAD_DEST = args.destination if args.destination else cfg["General"]["download_destination"]
	
	logger.info("Connecting to channel", CHANNEL)
	try:	
		with Telegram_client("Hugin", API_ID, API_HASH) as client:
			logger.success("A client-connection has been established")
			client.consume_files(CHANNEL)
	except ValueError as e:
		logger.error(f"Unable to connect to channel \"{CHANNEL}\". {e}")