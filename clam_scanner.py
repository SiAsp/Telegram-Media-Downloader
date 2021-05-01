from loguru import logger

import subprocess
import os

class Clam_scanner:
	def clam_eval(self, filename):
		logger.info(f"Running {filename} through ClamAV")
		command = f"clamscan -r --remove {filename}"

		process = subprocess.Popen(command.split(), stdout=subprocess.PIPE)
		output, error = process.communicate()
		num_infected_files, num_scanned_files = self.parse_clam_result(output)
		return int(num_infected_files), int(num_scanned_files)
			
	@staticmethod
	def parse_clam_result(output):		
		output = output.__str__()
		
		infected_pattern = "Infected files: "
		infected_index = output.find(infected_pattern)
		infected_result_pos = infected_index + len(infected_pattern)
		infected_result = output[infected_result_pos]
		
		scanned_pattern = "Scanned files: "
		scanned_index = output.find(scanned_pattern)
		scanned_result_pos = scanned_index + len(scanned_pattern)
		scanned_result = output[scanned_result_pos]

		return infected_result, scanned_result

	@staticmethod
	def rename_unscanned(filename):
		new_filename = "/".join(filename.split("/")[:-1]) + "/" + "UNSCANNED_" + filename.split("/")[-1]
		os.rename(filename, new_filename)
		logger.info(f"File renamed to {new_filename}")
		return new_filename