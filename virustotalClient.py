# # # # # # # # # # # # # # # # # # # # # # # # # # # 
# Telegram media-downloader							# 
# Written by: Sindre Asplem							# 
# Date: 06.11.20									# 
# # # # # # # # # # # # # # # # # # # # # # # # # # #  

import requests
import hashlib
import json

from loguru import logger

class Virustotal_API:
	def __init__(self, api_key):
		self.url = "https://www.virustotal.com/api/v3/"
		self.API_KEY = api_key

	def is_safe(self, resource):
		'''
		Searches Virustotal for given hash.
		:return: 0 if resource is malicious, 1 if not
		'''
		response = self.search(resource)
		return response

	def search(self, resource):
		_hash = self._hash(resource)
		endpoint = f'{self.url}files/{_hash}'
		headers = {'x_apikey': self.API_KEY}

		response = requests.get(endpoint, headers=headers)
		
		if response.status_code == 200:
			content = json.loads(response.text)
			data = content["data"]["attributes"]["last_analysis_stats"]
			
			if data["malicious"]:
				logger.warning(f"File {resource} has been reported malicious {data['malicious']} times")
				return 0

			elif data["suspicious"]:
				logger.warning(f"File {resource} has been reported suspicious {data['suspicious']} times")
				return 2
			
			else:
				logger.info(f"File {resource} is not known by Virustotal to be malicious or suspicious")
				return 1

		else:
			logger.warning(f"File {resource} not known by Virustotal")
			return 2

	@staticmethod
	def _hash(file):
		BUF_SIZE = 65536 # reading in 64kb chunks
		md5 = hashlib.md5()

		with open(file, 'rb') as f:
			while True:
				data = f.read(BUF_SIZE)
				if not data:
					break
				md5.update(data)

		return md5.hexdigest()