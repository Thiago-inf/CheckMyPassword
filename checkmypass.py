import requests
import hashlib
import sys

#geração da hash para a senha: https://passwordsgenerator.net/sha1-hash-generator/
#use somente os 5 primeiros caracteres
#esta API usa o formato SHA-1

STATUS_OK = 200

def request_api_data(query_char):
	url = 'https://api.pwnedpasswords.com/range/' + query_char
	response = requests.get(url)
	if response.status_code != STATUS_OK:
		raise RunTimeError(f'Error fetching: {response.status_code}, check the API and try again!')
	return response


def get_password_leaks_count(hashes_response, hash_to_check):
	hashes_response = (line.split(':') for line in hashes_response.text.splitlines())
	for hs, count in hashes_response:
		if hs == hash_to_check:
			return count
	return 0


def pwned_api_check(password):
	sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	first5_char, tail = sha1_password[:5], sha1_password[5:]
	response = request_api_data(first5_char)
	return get_password_leaks_count(response, tail)

def main():
	password_list = sys.argv[1:]
	for password in password_list:
		count = pwned_api_check(password)
		if count:
			print(f'this password: {password}\nwas found {count} times... you should not use it')
		else:
			print(f'this password: {password}\nwas NOT found. Carry on!')

if __name__ == '__main__':
	sys.exit(main())