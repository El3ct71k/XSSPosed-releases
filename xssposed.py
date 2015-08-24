__author__ = 'El3ct71k'

import logging
import urllib2
import exceptions
from time import sleep
from sys import stdout
import lxml.html as html_parser
import xml.etree.ElementTree as xml_parser
from argparse import ArgumentParser

# Global Variable
MAX_FEED = 5 # number of latest submissions
CONTAINER = set()
LOGGER = logging.getLogger('XSSPosed-releases')


def configure_logger(outfile):
	"""
		This function is responsible to configure logging object.
	"""
	# Check if logger exist
	if ('LOGGER' not in globals()) or (not LOGGER):
		raise Exception('Logger does not exists, Nothing to configure...')

	# Set logging level
	LOGGER.setLevel(logging.INFO)

	# Create console handler
	formatter = logging.Formatter(
		fmt='[%(asctime)s]\n%(message)s',
		datefmt='%d-%m-%Y %H:%M'
	)
	ch = logging.StreamHandler(stdout)
	ch.setFormatter(formatter)
	if outfile:     # If out file not None, he creates the file handler
		fh = logging.FileHandler(outfile)
		fh.setFormatter(logging.Formatter('%(message)s'))
		LOGGER.addHandler(fh)
	LOGGER.addHandler(ch)


def get_exploit(res):
	"""
		This function is responsible to extrace the exploit PoC from XSSPosed site.
	"""
	try:
		html_page = html_parser.fromstring(res)
		get_url = list(html_page.xpath('//a[@rel="nofollow"]'))[0].attrib['href']
		return get_url
	except IndexError:
		return "exploitation link not found"


def get_details(res):
	"""
		This function is responsible to extrace the exploit PoC from XSSPosed site.
	"""
	html_page = html_parser.fromstring(res)
	get_description = list(html_page.xpath('//td[@class="url"]'))[0].text
	status = str(list(html_page.xpath('//td[@class="col2"]'))[0].text)
	get_status = "Fixed%s" % status[3:] if status.startswith("Yes") else status
	post_data = False
	try:
		if str(html_page.xpath('//p[@class="urltxt"]')[2].text).startswith("HTTP POST"):
			post_data = html_page.xpath('//textarea[@name="post"]')[0].text
	except exceptions.IndexError:
		pass
	return {'description':get_description, 'status':get_status, 'post_data': post_data}

def get_feed(max_feed=5):
	"""
		This function is responsible to get RSS feeds.
	"""
	try:
		f = urllib2.urlopen("http://feeds.feedburner.com/XSSPosed")
	except urllib2.URLError:
		raise Exception("Internet connection problems")

	tree = xml_parser.fromstring(f.read())
	channel = tree.find('channel')
	items = channel.findall('item')
	for item in reversed(list(items)[0:max_feed]):
		link = list(item.iter('link'))[0].text
		if link not in CONTAINER:
			CONTAINER.add(link)
			site_response = urllib2.urlopen(link).read()
			details = get_details(site_response)
			yield {'title': list(item.iter('title'))[0].text, 'description': details['description'], 'link': link,
			       'status': str(details['status']),'exploit': get_exploit(site_response), 'post_data': details['post_data']}


def main(outfile):
	"""
		This function is responsible to extracts RSS feeds every 30 seconds
	"""
	configure_logger(outfile)
	while True:
		for items in get_feed(MAX_FEED):
			status, description, title, exploit, post_data, link = items.values()

			# Treatment in unicode
			status = status.encode('ascii', 'ignore') if isinstance(status, unicode) else status
			description = description.encode('ascii', 'ignore') if isinstance(description, unicode) else description
			post_data = "Post data: %s" % post_data if post_data else ''
			LOGGER.info("Title: {title}\nWebsite Description: {description}\nLink: {link}\nPacth status: {status}\nExploit: {exploit}\n{post_data}".format(
						title=title,
                        description=description,
						link=link,
                        status=status,
						exploit=exploit,
			            post_data=post_data
						))
		sleep(30)


if __name__ == '__main__':
	parser = ArgumentParser(description='XSSPosed-releases is tool that extracts latest XSS vulnerabilities published via XSSPosed.org that display a full disclosure about the malicious payload on the infected website')
	parser.add_argument("-o", "--output",
                        default=None,
                        help="Log file")
	main(parser.parse_args().output)