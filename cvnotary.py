import os, requests, json, re, gnupg

from time import time
from datetime import datetime
from copy import deepcopy
from sys import argv, exit

from fabric.api import settings, local

from vars import BASH_CMD, MD_FORMATTING_SENTINELS
from c_utils.cutils import DUtilsKey, DUtilsTransforms, load_config, parse_config_keys

class CameraVNotaryInstance():
	def __init__(self, file_path):
		self.obj = {'date_admitted' : time() * 1000}
		self.prop = load_config()

		if self.prop is None:
			self.prop = {}

		self.gpg = gnupg.GPG(homedir=self.prop['GNUPG_PATH'])

		secrets = [DUtilsKey(s, s, None, "none", DUtilsTransforms['NONE_IF_EMPTY']) for s in ['GPG_PWD']]

		self.prop.update(parse_config_keys(secrets, self.prop))
		self.prop.update({
			'date_admitted_str' : datetime.fromtimestamp(float(self.obj['date_admitted']/1000)).strftime("%B %d, %Y (%H:%M:%S)"),
			'date_admitted_str_md' : datetime.fromtimestamp(float(self.obj['date_admitted']/1000)).strftime("%Y-%m-%d %H:%M:%S"),
			'file_path' : file_path,
			'file_name' : file_path.split("/")[-1]
		})
		self.notarized = False

		self.obj['message'] = {
			'submit' : [
				"On %(date_admitted_str)s, I/we (%(USER_NAME)s) notarized document **%(file_name)s**.\n"
			]
		}

		if self.check_provenance():
			self.submit_to_blockchain()
			self.notarized = self.generate_message()

		if self.notarized:
			res_message = "Document %(file_name)s successfully notarized"
		else:
			res_message = "Sorry.  Could not notarize document %(file_name)s"

		print "** %s **" % (res_message % self.prop)

	def check_provenance(self):
		res, doc = self.__do_J3M_Lookup()
		if not res:
			print "Cannot find document in J3M Server"
			return False

		if not doc['j3m_verified'] or not doc['media_verified']:
			print "Document has no provenance.  Cannot notarize."
			return False

		self.prop['j3m_doc'] = doc
		j3m_message = []

		for a in self.prop['j3m_doc']['assets']:						
			if a['file_name'] == "j3m_raw.json":
				print "Found: verified j3m"

				r = self.__do_file_download(a['file_name'])
				if not r:
					return False
				
				from hashlib import sha256
				h = sha256()
				h.update(r.content)
				self.prop['j3m_hash'] = h.hexdigest()

				j3m_message.append("SHA256 hash of J3M metadata: **%(j3m_hash)s**\n")
				continue

			if 'tags' not in a.keys():
				continue
				
			if "camerav_notarization_doc" in a['tags']:
				print "Found: notarized receipt"

				r = self.__do_file_download(a['file_name'])
				if not r:
					return False

				self.prop['j3m_notary_receipt'] = r.content

				code_block_sentinels = MD_FORMATTING_SENTINELS['code_block'] \
					["standard" if not self.prop['MD_FORMATTING'] else \
					self.prop['MD_FORMATTING']]
				
				j3m_message.extend([
					"Signed receipt from J3M server:\n",
					code_block_sentinels[0],
					"\n%(j3m_notary_receipt)s\n",
					code_block_sentinels[1]
				])

		if len(j3m_message) != 0:
			self.obj['message']['j3m'] = j3m_message

		return True

	def __do_bash(self, cmd):
		with settings(warn_only=True):
			b = local(cmd, capture=True)

		content = None
		res = False if b.return_code != 0 else True
		
		try:
			content = b.stdout
		except Exception as e:
			print e, type(e)

		return res, content

	def __do_file_download(self, file):
		try:
			r = requests.get("%s/%s" % \
				(self.prop['J3M_SERVER'], os.path.join("files", self.prop['j3m_doc']['base_path'], file)))
			if r.status_code == 200:
				return r
			else:
				print "BAD STATUS CODE: %d" % r.status_code
			
		except Exception as e:
			print e, type(e)

		return False

	def __do_J3M_Lookup(self):
		if not self.prop['J3M_SERVER']:
			return False

		h = None

		if 'J3M_SERVER_ID_LEN' not in self.prop.keys() or self.prop['J3M_SERVER_ID_LEN'] == 40:
			from hashlib import sha1
			h = sha1()
		elif self.prop['J3M_SERVER_ID_LEN'] == 32:
			from hashlib import md5
			h = md5()

		if h is None:
			return False

		with open(self.prop['file_path'], 'rb') as f:
			for chunk in iter(lambda: f.read(4096), b''):
				h.update(chunk)

		self.prop['doc_hash'] = h.hexdigest()

		url = "%s/documents/?_id=%s" % (self.prop['J3M_SERVER'], self.prop['doc_hash'])

		try:
			r = requests.get(url)
			if r.status_code != 200:
				return False

			doc = json.loads(r.content)
			if 'data' in doc.keys():
				return True, doc['data']

		except Exception as e:
			print e, type(e)

		return False

	def __do_POE_request(self, url, data):
		if not self.prop['POE_SERVER']:
			return False, None

		url = "%s/%s" % (self.prop['POE_SERVER'], url)

		try:
			r = requests.post(url, data=data)
			return False if r.status_code != 200 else True, json.loads(r.content)

		except Exception as e:
			print "could not do POE api call to %s" % url
			print e, type(e)

		return False, None

	def __check_POE_status(self):
		res, poe_entry = self.__do_POE_request("api/v1/status", {'d' : self.prop['j3m_hash']})
		if not res:
			return None

		return poe_entry

	def generate_message(self):
		self.prop['notarized_message_path'] = os.path.join(self.prop['NOTARY_DOC_DIR'], \
			"%s.md" % self.prop['doc_hash'])

		front_matter = None if not self.prop['MD_FORMATTING'] \
			else MD_FORMATTING_SENTINELS['frontmatter'][self.prop['MD_FORMATTING']]

		message_digest = []

		try:
			with open(self.prop['notarized_message_path'], 'wb+') as message:				
				if front_matter:
					message.write("\n".join([f % self.prop for f in front_matter]))

				message.write('<!-- begin_notarized_doc -->\n')
				
				for m in ['submit', 'j3m', 'poe']:
					if m not in self.obj['message'].keys():
						continue

					section = "%s\n" % "\n".join([l % self.prop for l in self.obj['message'][m]])
					message_digest.append(section)
					message.write(section)
				
				message.write('<!-- end_notarized_doc -->\n')

				code_block_sentinels = MD_FORMATTING_SENTINELS['code_block'] \
					["standard" if not self.prop['MD_FORMATTING'] else \
					self.prop['MD_FORMATTING']]

				self.obj['message']['digest'] = [
					"\n---",
					"\n###%(USER_NAME)s hereby notarizes this document:\n",
					code_block_sentinels[0],
					"\n",
					self.sign_message("\n".join(message_digest)),
					code_block_sentinels[1]
				]

				message.write("\n".join([l % self.prop for l in self.obj['message']['digest']]))

			return True

		except Exception as e:
			print "COULD NOT GENERATE MESSAGE:"
			print e, type(e)

		return False

	def sign_message(self, message):
		signed_message = self.gpg.sign(message, default_key=self.prop['GPG_KEY_ID'],
			passphrase=self.prop['GPG_PWD'], clearsign=False)
		
		try:
			if len(signed_message.data) > 0:
				return signed_message.data
		except Exception as e:
			print "COULD NOT SIGN MESSAGE"
			print e, type(e)

		return None
		
	def submit_to_blockchain(self):
		poe_entry = self.__check_POE_status()
		if poe_entry is None:
			return False

		if not poe_entry['success']:
			if poe_entry['reason'] == "nonexistent":
				res, poe_entry = self.__do_POE_request("api/v1/register", {'d' : self.prop['j3m_hash']})

				if not res:
					return False

				if not poe_entry['success']:
					print "Could not register j3m hash to Proof Of Existence server."
					return False

				new_status = self.__check_POE_status()
				if new_status is None:
					print "Error: poor doc entry :("
					return False

				poe_entry['status'] = new_status['status']
			else:
				print "Unknown error with Proof Of Existence server. (reason: %s)" % poe_entry['reason']
				return False

		self.prop.update(poe_entry)

		if self.prop['status'] == "registered" and self.prop['pay_address'] and self.prop['price']:
			from fabric.operations import prompt

			print "\n** In order to fully notarize this document on the Blockchain, you must pay %(price)d mBtc to Bitcoin address %(pay_address)s **\n" % self.prop

			new_status = self.__check_POE_status()
			if new_status is None:
				return False

			self.prop.update(new_status)

		if self.prop['status'] in ["pending", "confirmed", "registered"]:
			try:
				poe_message = [
					"\nThis media item's J3M metadata has been submitted to a [Proof of Existence](http://proofofexistence.com/) server.",
				]

				if 'POE_SERVER_ALIAS' in self.prop.keys():
					poe_message += [
						"\nTo view its status on the blockchain, please check [here](%(POE_SERVER_ALIAS)s/detail/%(j3m_hash)s)."
					]

				self.obj['message']['poe'] = poe_message
				return True

			except Exception as e:
				print "could not update notary message"
				print e, type(e)

		return False

if __name__ == "__main__":
	res = False

	try:
		cni = CameraVNotaryInstance(argv[1])
		res = cni.notarized
	except Exception as e:
		print e, type(e)

	exit(0 if res else -1)

