import requests
import hashlib
import sys

'''
we get the first 5 hash characters and check whether it exists in server so that the pwd can be confidential 
from the internet. the RES gathers all the data with the same hash character from the server and returns 
it.

'''
def request_api_data(query_char):

	url = 'https://api.pwnedpasswords.com/range/'+ query_char
	res = requests.get(url)
	if res.status_code != 200:
		raise RuntimeError(f'Error fetching: {res.status_code}, check api and try again.')
	return res

'''
we get the list of all the hash values with the number of times it has been leaked in the internet.
we also send our hash password to check whether it matches with the data and return the number of times
the data has been leaked.
'''

def get_pwd_leak_count(hashes, hash_check):
	hashes = (line.split(':') for line in hashes.text.splitlines())
	for h, count in hashes:
		if h == hash_check:
			return count
	return 0

'''
we get the passwords from the user and convert it to SHA1 hash so that the password to be searched over the
internet will be difficult to track it.
'''

def pwned_api_check(password):
	sha1password = hashlib.sha1(password.encode('UTF-8')).hexdigest().upper()	#password is converted to hexadecimals, to uppercase.
	first5_char, tail = sha1password[:5], sha1password[5:]
	response = request_api_data(first5_char)	
	return get_pwd_leak_count(response,tail)


def main(args):

	for password in args:
		count = pwned_api_check(password)
		if count:
			print(f'The password : {password} has been leaked {count} times! 	Please change it ASAP!')
		else:
			print(f'The password : {password} has not been leaked!')
	return 'Done!'

if __name__ == '__main__':
	sys.exit(main(sys.argv[1:])) 	#accepts passwords after entering the file name and exits after the program is run.
